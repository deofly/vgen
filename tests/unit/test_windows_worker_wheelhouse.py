from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import stat
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "windows_worker_wheelhouse",
    ROOT / "tools" / "windows_worker_wheelhouse.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

BASE_WHEEL_FILES = {
    "sample/__init__.py": b"VALUE = 1\n",
    "sample-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
}
METADATA_NAME = "sample-1.0.dist-info/METADATA"
RECORD_NAME = "sample-1.0.dist-info/RECORD"


def _wheel_files(metadata: bytes) -> dict[str, bytes]:
    files = {**BASE_WHEEL_FILES, METADATA_NAME: metadata}
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name in sorted(files, key=lambda value: value.encode("utf-8")):
        value = files[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=")
        writer.writerow((name, f"sha256={digest.decode('ascii')}", len(value)))
    writer.writerow((RECORD_NAME, "", ""))
    files[RECORD_NAME] = record.getvalue().encode("utf-8")
    return files


def _write_wheel(
    path: Path,
    *,
    files: dict[str, bytes],
    names: list[str],
    create_system: int,
    mode: int,
    compression: int,
) -> None:
    with zipfile.ZipFile(path, "x", compression=compression) as archive:
        for name in names:
            info = zipfile.ZipInfo(name, (2026, 8, 27, 12, 34, 56))
            info.create_system = create_system
            info.external_attr = mode << 16
            info.compress_type = compression
            archive.writestr(info, files[name])


def test_source_built_wheels_are_canonical_across_host_zip_metadata(tmp_path: Path) -> None:
    windows = tmp_path / "windows.whl"
    unix = tmp_path / "unix.whl"
    unix_metadata = b"Name: sample\nVersion: 1.0\n\nLine one\r\nLine two\n"
    windows_metadata = unix_metadata.replace(b"\n", b"\r\n")
    unix_files = _wheel_files(unix_metadata)
    windows_files = _wheel_files(windows_metadata)
    names = list(unix_files)
    _write_wheel(
        windows,
        files=windows_files,
        names=list(reversed(names)),
        create_system=0,
        mode=stat.S_IFREG | 0o666,
        compression=zipfile.ZIP_DEFLATED,
    )
    _write_wheel(
        unix,
        files=unix_files,
        names=names,
        create_system=3,
        mode=stat.S_IFREG | 0o600,
        compression=zipfile.ZIP_STORED,
    )

    MODULE._canonicalize_built_wheel(windows)
    MODULE._canonicalize_built_wheel(unix)

    assert windows.read_bytes() == unix.read_bytes()
    with zipfile.ZipFile(windows) as archive:
        infos = archive.infolist()
        assert [info.filename for info in infos] == sorted(
            unix_files,
            key=lambda value: value.encode("utf-8"),
        )
        assert archive.testzip() is None
        assert all(info.date_time == (2020, 2, 2, 0, 0, 0) for info in infos)
        assert all(info.create_system == 3 for info in infos)
        assert all(info.compress_type == zipfile.ZIP_STORED for info in infos)
        assert all(info.external_attr >> 16 == stat.S_IFREG | 0o644 for info in infos)
        assert archive.read(METADATA_NAME).endswith(b"Line one\nLine two\n")
        record = archive.read(RECORD_NAME).decode("utf-8")
        assert record.endswith(f"{RECORD_NAME},,\n")
        normalized_metadata = archive.read(METADATA_NAME)
        digest = base64.urlsafe_b64encode(hashlib.sha256(normalized_metadata).digest()).rstrip(b"=")
        assert (
            f"{METADATA_NAME},sha256={digest.decode('ascii')},{len(normalized_metadata)}\n"
            in record
        )


@pytest.mark.parametrize("unsafe_name", ["../escape.py", "sample\\escape.py"])
def test_source_built_wheel_canonicalization_rejects_unsafe_paths(
    tmp_path: Path,
    unsafe_name: str,
) -> None:
    wheel = tmp_path / "unsafe.whl"
    with zipfile.ZipFile(wheel, "x") as archive:
        archive.writestr(unsafe_name, b"unsafe")

    with pytest.raises(MODULE.WheelhouseBuildError, match="unsafe source-built wheel"):
        MODULE._canonicalize_built_wheel(wheel)
