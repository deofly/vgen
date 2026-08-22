#!/usr/bin/env python3
"""Refresh a private Windows Worker bundle without changing its Worker identity."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import tempfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

_BUNDLE_FORMAT = "vgen-windows-worker-bundle"
_BUNDLE_VERSION = 1
_CREDENTIAL_NAME = "worker-credentials.json"
_LAUNCHER_NAME = "start-worker.cmd"
_MANIFEST_NAME = "vgen-worker-bundle.json"
_POLICY_NAME = "comfyui-minimax-h3-policy.yaml"
_SETUP_NAME = "setup-worker.ps1"
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


class RepackError(RuntimeError):
    """The input is not a safe, internally consistent Worker bundle."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_unique(archive: zipfile.ZipFile, name: str) -> bytes:
    matches = [info for info in archive.infolist() if info.filename == name]
    if len(matches) != 1:
        raise RepackError(f"expected exactly one {name} entry")
    return archive.read(matches[0])


def _safe_entries(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise RepackError("bundle contains duplicate ZIP entries")
    for name in names:
        if "\\" in name:
            raise RepackError(f"unsafe bundle entry: {name}")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or len(path.parts) != 1 or name.endswith("/"):
            raise RepackError(f"unsafe bundle entry: {name}")
    return infos


def _wheel_bytes_identity(name: str, wheel: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise RepackError("Worker wheel contains duplicate entries")
            for entry in names:
                normalized = PurePosixPath(entry.replace("\\", "/"))
                if (
                    entry.startswith(("/", "\\"))
                    or "\\" in entry
                    or ".." in normalized.parts
                ):
                    raise RepackError("Worker wheel contains an unsafe path")
            metadata_names = [entry for entry in names if entry.endswith(".dist-info/METADATA")]
            wheel_names = [entry for entry in names if entry.endswith(".dist-info/WHEEL")]
            if len(metadata_names) != 1:
                raise RepackError("wheel must contain exactly one METADATA file")
            if len(wheel_names) != 1:
                raise RepackError("wheel must contain exactly one WHEEL file")
            metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
            wheel_metadata = archive.read(wheel_names[0]).decode("utf-8")
    except zipfile.BadZipFile as exc:
        raise RepackError("Worker wheel is not a valid wheel archive") from exc
    except UnicodeDecodeError as exc:
        raise RepackError("Worker wheel metadata is not UTF-8") from exc
    if metadata.get("Name", "").lower() != "vgen":
        raise RepackError("Worker wheel package name must be vgen")
    version = metadata.get("Version", "")
    if _VERSION.fullmatch(version) is None:
        raise RepackError("Worker wheel must use a three-part release version")
    expected_name = f"vgen-{version}-py3-none-any.whl"
    if name != expected_name:
        raise RepackError(f"Worker wheel must be named {expected_name}")
    if "Tag: py3-none-any" not in wheel_metadata.splitlines():
        raise RepackError("Worker wheel must use the py3-none-any tag")
    return version


def _wheel_identity(wheel_path: Path) -> tuple[str, bytes]:
    wheel = wheel_path.read_bytes()
    version = _wheel_bytes_identity(wheel_path.name, wheel)
    return version, wheel


def _manifest(value: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepackError("bundle manifest is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise RepackError("bundle manifest must be an object")
    if parsed.get("format") != _BUNDLE_FORMAT or parsed.get("version") != _BUNDLE_VERSION:
        raise RepackError("unsupported Worker bundle format")
    wheel = parsed.get("wheel")
    if not isinstance(wheel, dict) or not isinstance(wheel.get("name"), str):
        raise RepackError("bundle manifest does not identify its Worker wheel")
    return parsed


def repack_bundle(
    source_path: Path,
    wheel_path: Path,
    setup_path: Path,
    output_path: Path,
) -> tuple[str, str]:
    """Atomically refresh code while preserving every private identity byte."""

    source_path = source_path.resolve()
    wheel_path = wheel_path.resolve()
    setup_path = setup_path.resolve()
    output_path = output_path.resolve()
    version, wheel_bytes = _wheel_identity(wheel_path)
    setup_bytes = setup_path.read_bytes()

    try:
        with zipfile.ZipFile(source_path) as source:
            infos = _safe_entries(source)
            contents = {info.filename: source.read(info) for info in infos}
    except zipfile.BadZipFile as exc:
        raise RepackError("source Worker bundle is not a valid ZIP archive") from exc

    credentials = _read_bundle_value(contents, _CREDENTIAL_NAME)
    manifest = _manifest(_read_bundle_value(contents, _MANIFEST_NAME))
    previous_wheel = str(manifest["wheel"]["name"])
    if previous_wheel not in contents or not previous_wheel.startswith("vgen-"):
        raise RepackError("bundle manifest Worker wheel is missing")
    policy = manifest.get("policy")
    if manifest.get("worker_credentials") != _CREDENTIAL_NAME:
        raise RepackError("bundle manifest Worker credential name is invalid")
    if not isinstance(policy, dict) or policy.get("name") != _POLICY_NAME:
        raise RepackError("bundle manifest policy name is invalid")
    expected_entries = {
        _CREDENTIAL_NAME,
        _LAUNCHER_NAME,
        _MANIFEST_NAME,
        _POLICY_NAME,
        _SETUP_NAME,
        previous_wheel,
    }
    if set(contents) != expected_entries:
        raise RepackError("source Worker bundle must contain exactly the six reviewed files")
    _wheel_bytes_identity(previous_wheel, contents[previous_wheel])
    if manifest["wheel"].get("sha256") != _sha256(contents[previous_wheel]):
        raise RepackError("source Worker wheel hash does not match its manifest")
    if policy.get("sha256") != _sha256(contents[_POLICY_NAME]):
        raise RepackError("source Worker policy hash does not match its manifest")

    manifest["wheel"] = {
        "name": wheel_path.name,
        "sha256": _sha256(wheel_bytes),
        "version": version,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    info_by_name = {info.filename: info for info in infos}
    replacements = {
        _MANIFEST_NAME: manifest_bytes,
        _SETUP_NAME: setup_bytes,
        wheel_path.name: wheel_bytes,
    }
    retained_names = [name for name in contents if name != previous_wheel]
    if wheel_path.name not in retained_names:
        retained_names.append(wheel_path.name)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent, delete=False
        ) as temporary:
            temporary_name = temporary.name
        os.chmod(temporary_name, 0o600)
        with zipfile.ZipFile(temporary_name, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for name in retained_names:
                value = replacements[name] if name in replacements else contents[name]
                info = info_by_name.get(name)
                if info is None:
                    info = zipfile.ZipInfo(name)
                    info.external_attr = 0o600 << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(info, value)
        with zipfile.ZipFile(temporary_name) as rebuilt:
            rebuilt_infos = _safe_entries(rebuilt)
            if {info.filename for info in rebuilt_infos} != (
                expected_entries - {previous_wheel} | {wheel_path.name}
            ):
                raise RepackError("rebuilt Worker bundle contains unexpected files")
            if _read_unique(rebuilt, _CREDENTIAL_NAME) != credentials:
                raise RepackError("Worker credential changed during repack")
            if _read_unique(rebuilt, _MANIFEST_NAME) != manifest_bytes:
                raise RepackError("Worker bundle manifest verification failed")
        os.replace(temporary_name, output_path)
        temporary_name = None
        os.chmod(output_path, 0o600)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)

    return version, _sha256(credentials)


def _read_bundle_value(contents: dict[str, bytes], name: str) -> bytes:
    try:
        return contents[name]
    except KeyError as exc:
        raise RepackError(f"bundle is missing {name}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--setup", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        version, credential_fingerprint = repack_bundle(
            arguments.source, arguments.wheel, arguments.setup, arguments.output
        )
    except (OSError, RepackError) as exc:
        parser.error(str(exc))
    print(f"Repacked Worker bundle for VGen {version}: {arguments.output}")
    print(f"Worker credential preserved (SHA-256 {credential_fingerprint})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
