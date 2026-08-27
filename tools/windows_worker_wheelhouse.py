"""Build the reviewed offline Windows Worker dependency wheelhouse.

The public Worker installer targets CPython 3.11 on 64-bit Windows.  Every
download is selected by an exact version and a single SHA-256 hash.  The two
upstream projects which do not publish wheels are rebuilt as deterministic
pure-Python wheels with pinned build tools; their output hashes are part of
this source contract and fail closed on any drift.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPOSITORY = Path(__file__).resolve().parents[1]
LOCK_ROOT = REPOSITORY / "requirements"
BINARY_LOCK = LOCK_ROOT / "windows-worker-binary.lock"
SOURCE_LOCK = LOCK_ROOT / "windows-worker-source.lock"
BUILD_LOCK = LOCK_ROOT / "windows-worker-build.lock"
_BOOTSTRAP_PIP = "pip-26.2-py3-none-any.whl"
_SOURCE_DATE_EPOCH = "1580601600"
_MAX_SOURCE_ENTRIES = 4096
_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_EXPECTED_SOURCE_ROOTS = {
    "crcmod-1.7.tar.gz": "crcmod-1.7",
    "oss2-2.19.1.tar.gz": "oss2-2.19.1",
}
_SOURCE_ARTIFACTS = {
    "crcmod-1.7.tar.gz": (
        "crcmod",
        "1.7",
        "https://files.pythonhosted.org/packages/6b/b0/e595ce2a2527e169c3bcd6c33d2473c1918e0b7f6826a043ca1245dd4e5b/crcmod-1.7.tar.gz",
        "dc7051a0db5f2bd48665a990d3ec1cc305a466a77358ca4492826f41f283601e",
    ),
    "oss2-2.19.1.tar.gz": (
        "oss2",
        "2.19.1",
        "https://files.pythonhosted.org/packages/df/b5/f2cb1950dda46ac2284d6c950489fdacd0e743c2d79a347924d3cc44b86f/oss2-2.19.1.tar.gz",
        "a8ab9ee7eb99e88a7e1382edc6ea641d219d585a7e074e3776e9dec9473e59c1",
    ),
}
_EXPECTED_BUILT_WHEELS = {
    "crcmod-1.7-py3-none-any.whl": (
        "57efbf1bf9719f1593c583ddb65749b2c5a42181d167ce8a8eef1416c20f2b2c"
    ),
    "oss2-2.19.1-py3-none-any.whl": (
        "4d6dcec69b4c391c9e57e00579543a689eee7ed0d9620801eefbbdc8615f38d6"
    ),
}
_LOCK_FILES = (BINARY_LOCK, SOURCE_LOCK, BUILD_LOCK)
_LOCK_LINE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*) "
    r"--hash=sha256:([0-9a-f]{64})$"
)
_CRCMOD_EXTENSION_BLOCK = (
    b"ext_modules=[ \n"
    b"    Extension('crcmod._crcfunext', [os.path.join(base_dir,'src/_crcfunext.c'), ],\n"
    b"    ),\n"
    b"],"
)


class WheelhouseBuildError(RuntimeError):
    """A pinned download or deterministic wheel build failed safely."""


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise WheelhouseBuildError("reviewed source artifact URL redirected unexpectedly")


@contextmanager
def _reviewed_umask():
    """Keep source-build metadata stable when the invoking shell has a strict umask."""

    if os.name == "nt":
        yield
        return
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise WheelhouseBuildError(f"unsafe filesystem entry: {path.name}") from exc
    return path.is_symlink() or bool(attributes & 0x400)


def _read_hash_lock(path: Path) -> dict[str, tuple[str, str]]:
    """Read the narrow one-artifact-per-distribution lock contract."""

    entries: dict[str, tuple[str, str]] = {}
    try:
        if _is_reparse(path) or not path.is_file():
            raise OSError
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise WheelhouseBuildError(f"Windows Worker lock is unavailable: {path.name}") from exc
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _LOCK_LINE.fullmatch(line)
        if match is None:
            raise WheelhouseBuildError(f"Windows Worker lock is malformed: {path.name}")
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        if name in entries:
            raise WheelhouseBuildError(
                f"Windows Worker lock has a duplicate distribution: {path.name}"
            )
        entries[name] = (match.group(2), match.group(3))
    if not entries:
        raise WheelhouseBuildError(f"Windows Worker lock is empty: {path.name}")
    return entries


def committed_worker_lock_set_sha256() -> str:
    """Digest the three committed locks with unambiguous filename framing."""

    digest = hashlib.sha256(b"vgen-windows-worker-lock-set-v1\0")
    for path in _LOCK_FILES:
        try:
            if _is_reparse(path) or not path.is_file():
                raise OSError
            value = path.read_bytes()
        except OSError as exc:
            raise WheelhouseBuildError(
                f"Windows Worker lock is unavailable: {path.name}"
            ) from exc
        name = path.name.encode("ascii")
        digest.update(len(name).to_bytes(2, "big"))
        digest.update(name)
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def expected_committed_runtime_hashes() -> frozenset[str]:
    """Return the exact third-party wheel hashes authorized by the locks."""

    binary = _read_hash_lock(BINARY_LOCK)
    hashes = {digest for _version, digest in binary.values()}
    hashes.update(_EXPECTED_BUILT_WHEELS.values())
    if len(hashes) != len(binary) + len(_EXPECTED_BUILT_WHEELS):
        raise WheelhouseBuildError("Windows Worker runtime lock contains duplicate artifacts")
    return frozenset(hashes)


def validate_committed_worker_wheelhouse(root: Path) -> None:
    """Reject a prebuilt wheelhouse that differs from the committed lock set."""

    try:
        if _is_reparse(root):
            raise OSError
        resolved = root.resolve(strict=True)
        paths = list(resolved.iterdir())
    except OSError as exc:
        raise WheelhouseBuildError("reviewed Worker wheelhouse is unavailable") from exc
    if not resolved.is_dir():
        raise WheelhouseBuildError("reviewed Worker wheelhouse is not a directory")
    actual: set[str] = set()
    for path in paths:
        if _is_reparse(path) or not path.is_file() or path.suffix != ".whl":
            raise WheelhouseBuildError(
                "reviewed Worker wheelhouse contains a non-wheel or unsafe entry"
            )
        digest = _sha256(path)
        if digest in actual:
            raise WheelhouseBuildError("reviewed Worker wheelhouse contains duplicate artifacts")
        actual.add(digest)
    if actual != expected_committed_runtime_hashes():
        raise WheelhouseBuildError(
            "reviewed Worker wheelhouse differs from the committed runtime locks"
        )


def _run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, check=False, env=env)
    if result.returncode != 0:
        raise WheelhouseBuildError(
            f"wheelhouse command failed with exit code {result.returncode}: {command[0]}"
        )


def _download_lock(
    python: Path,
    lock: Path,
    destination: Path,
    *,
    binary: bool,
    windows_target: bool,
) -> None:
    command = [
        str(python),
        "-I",
        "-B",
        "-m",
        "pip",
        "download",
        "--disable-pip-version-check",
        "--no-deps",
        "--require-hashes",
        "--dest",
        str(destination),
        "--only-binary=:all:" if binary else "--no-binary=:all:",
    ]
    if windows_target:
        command.extend(
            [
                "--platform",
                "win_amd64",
                "--python-version",
                "3.11",
                "--implementation",
                "cp",
                "--abi",
                "cp311",
            ]
        )
    command.extend(["-r", str(lock)])
    _run(command)


def _source_lock_contract() -> dict[str, tuple[str, str]]:
    """Parse the human-auditable source lock without executing package metadata."""

    entries: dict[str, tuple[str, str]] = {}
    try:
        lines = SOURCE_LOCK.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise WheelhouseBuildError("Windows Worker source lock is unavailable") from exc
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        prefix, separator, digest = stripped.partition(" --hash=sha256:")
        name, version_separator, version = prefix.partition("==")
        if (
            separator != " --hash=sha256:"
            or version_separator != "=="
            or not name
            or not version
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or name in entries
        ):
            raise WheelhouseBuildError("Windows Worker source lock is malformed")
        entries[name] = (version, digest)
    return entries


def _download_sources(destination: Path) -> None:
    """Fetch exact sdists directly, without asking pip to execute their build hooks."""

    expected_lock = {
        name: (version, digest)
        for _filename, (name, version, _url, digest) in _SOURCE_ARTIFACTS.items()
    }
    if _source_lock_contract() != expected_lock:
        raise WheelhouseBuildError("Windows Worker source lock differs from reviewed artifacts")
    opener = build_opener(_RejectRedirects())
    for filename, (_name, _version, url, expected_digest) in sorted(_SOURCE_ARTIFACTS.items()):
        target = destination / filename
        temporary = destination / f".{filename}.part"
        digest = hashlib.sha256()
        size = 0
        try:
            request = Request(url, headers={"User-Agent": "vgen-wheelhouse-builder/1"})
            with opener.open(request, timeout=30) as response, temporary.open("xb") as handle:
                if response.geturl() != url:
                    raise WheelhouseBuildError(f"reviewed source artifact URL changed: {filename}")
                declared_size = response.headers.get("Content-Length")
                if declared_size is not None and (
                    not declared_size.isdigit() or int(declared_size) > _MAX_SOURCE_BYTES
                ):
                    raise WheelhouseBuildError(
                        f"reviewed source artifact has an invalid size: {filename}"
                    )
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > _MAX_SOURCE_BYTES:
                        raise WheelhouseBuildError(
                            f"reviewed source artifact is too large: {filename}"
                        )
                    digest.update(block)
                    handle.write(block)
            if size == 0 or digest.hexdigest() != expected_digest:
                raise WheelhouseBuildError(
                    f"reviewed source artifact failed SHA-256 verification: {filename}"
                )
            os.replace(temporary, target)
        except WheelhouseBuildError:
            raise
        except (HTTPError, URLError, OSError) as exc:
            raise WheelhouseBuildError(
                f"reviewed source artifact could not be downloaded: {filename}"
            ) from exc
        finally:
            temporary.unlink(missing_ok=True)


def _venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _pip_from_wheel(python: Path, pip_wheel: Path) -> list[str]:
    # A wheel is not a zipapp.  Insert the reviewed wheel on sys.path and call
    # pip's supported internal CLI entrypoint explicitly.
    bootstrap = (
        "import sys; "
        "sys.path.insert(0, sys.argv.pop(1)); "
        "from pip._internal.cli.main import main; "
        "raise SystemExit(main())"
    )
    return [str(python), "-I", "-B", "-c", bootstrap, str(pip_wheel)]


def _safe_extract_source(archive_path: Path, destination: Path, expected_root: str) -> Path:
    total = 0
    names: set[str] = set()
    folded: set[str] = set()
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_SOURCE_ENTRIES:
                raise WheelhouseBuildError(f"invalid source entry count: {archive_path.name}")
            for member in members:
                raw = member.name
                if "\\" in raw or "\x00" in raw or raw.startswith("/"):
                    raise WheelhouseBuildError(f"unsafe source path: {archive_path.name}")
                path = PurePosixPath(raw.rstrip("/"))
                if (
                    not path.parts
                    or path.parts[0] != expected_root
                    or any(part in {"", ".", ".."} for part in path.parts)
                ):
                    raise WheelhouseBuildError(f"unsafe source root: {archive_path.name}")
                normalized = path.as_posix()
                key = normalized.casefold()
                if normalized in names or key in folded:
                    raise WheelhouseBuildError(f"duplicate source path: {archive_path.name}")
                names.add(normalized)
                folded.add(key)
                if member.isdir():
                    directory = destination / normalized
                    directory.mkdir(parents=True, exist_ok=True)
                    directory.chmod(0o755)
                    continue
                if not member.isfile() or member.size < 0:
                    raise WheelhouseBuildError(f"non-regular source entry: {archive_path.name}")
                total += member.size
                if total > _MAX_SOURCE_BYTES:
                    raise WheelhouseBuildError(f"source archive is too large: {archive_path.name}")
                target = destination / normalized
                target.parent.mkdir(parents=True, exist_ok=True)
                target.parent.chmod(0o755)
                incoming = archive.extractfile(member)
                if incoming is None:
                    raise WheelhouseBuildError(f"unreadable source entry: {archive_path.name}")
                with incoming, target.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
                target.chmod(0o644)
    except (OSError, tarfile.TarError) as exc:
        raise WheelhouseBuildError(f"unreadable source archive: {archive_path.name}") from exc
    extracted_root = destination / expected_root
    try:
        extracted_root.chmod(0o755)
        for path in extracted_root.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
    except OSError as exc:
        raise WheelhouseBuildError(
            f"source permissions could not be normalized: {archive_path.name}"
        ) from exc
    return extracted_root


def _prepare_crcmod_source(root: Path) -> None:
    setup = root / "setup.py"
    try:
        value = setup.read_bytes()
    except OSError as exc:
        raise WheelhouseBuildError("crcmod setup.py is unavailable") from exc
    if value.count(_CRCMOD_EXTENSION_BLOCK) != 1:
        raise WheelhouseBuildError("crcmod extension declaration no longer matches review")
    setup.write_bytes(value.replace(_CRCMOD_EXTENSION_BLOCK, b"ext_modules=[],"))


def _build_sources(
    python: Path,
    downloads: Path,
    build_downloads: Path,
    source_downloads: Path,
    work: Path,
) -> Path:
    pip_wheel = downloads / _BOOTSTRAP_PIP
    if not pip_wheel.is_file() or pip_wheel.is_symlink():
        raise WheelhouseBuildError("reviewed bootstrap pip wheel is missing")
    build_environment = work / "build-environment"
    venv.EnvBuilder(with_pip=False, clear=False, symlinks=False).create(build_environment)
    build_python = _venv_python(build_environment)
    if not build_python.is_file():
        raise WheelhouseBuildError("isolated source-build Python was not created")
    _run(
        [
            *_pip_from_wheel(build_python, pip_wheel),
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--find-links",
            str(build_downloads),
            "--require-hashes",
            "-r",
            str(BUILD_LOCK),
        ]
    )

    source_root = work / "sources"
    source_root.mkdir()
    prepared: list[Path] = []
    source_files = {path.name: path for path in source_downloads.iterdir() if path.is_file()}
    if set(source_files) != set(_EXPECTED_SOURCE_ROOTS):
        raise WheelhouseBuildError("source lock produced an unexpected artifact set")
    for name, expected_root in sorted(_EXPECTED_SOURCE_ROOTS.items()):
        extracted = _safe_extract_source(source_files[name], source_root, expected_root)
        if name == "crcmod-1.7.tar.gz":
            _prepare_crcmod_source(extracted)
        prepared.append(extracted)

    output = work / "built-wheels"
    output.mkdir()
    environment = os.environ.copy()
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": _SOURCE_DATE_EPOCH,
            "TZ": "UTC",
        }
    )
    _run(
        [
            *_pip_from_wheel(build_python, pip_wheel),
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(output),
            *(str(path) for path in prepared),
        ],
        env=environment,
    )
    actual = {path.name: _sha256(path) for path in output.glob("*.whl")}
    if actual != _EXPECTED_BUILT_WHEELS:
        raise WheelhouseBuildError(
            "source-built wheels differ from the reviewed filenames or SHA-256 values"
        )
    return output


def build_worker_wheelhouse(
    output: Path,
    *,
    python: Path | None = None,
) -> Path:
    """Materialize an atomic, hash-locked Windows Worker wheelhouse."""

    expanded = output.expanduser()
    if expanded.is_symlink():
        raise WheelhouseBuildError(f"refusing to overwrite wheelhouse: {expanded}")
    target = expanded.resolve()
    if target.exists():
        raise WheelhouseBuildError(f"refusing to overwrite wheelhouse: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    selected_python = Path(sys.executable if python is None else python).resolve()
    try:
        version_check = subprocess.run(
            [
                str(selected_python),
                "-I",
                "-B",
                "-c",
                (
                    "import sys; raise SystemExit(0 if "
                    "sys.implementation.name == 'cpython' and "
                    "(3, 11) <= sys.version_info[:2] <= (3, 14) else 1)"
                ),
            ],
            check=False,
        )
    except OSError as exc:
        raise WheelhouseBuildError("the selected wheelhouse builder Python is unavailable") from exc
    if version_check.returncode != 0:
        raise WheelhouseBuildError(
            "the reviewed Windows Worker wheelhouse must be built with CPython 3.11 through 3.14"
        )
    with _reviewed_umask():
        with tempfile.TemporaryDirectory(prefix="vgen-worker-wheelhouse-") as temporary:
            work = Path(temporary)
            binary_downloads = work / "binary-downloads"
            source_downloads = work / "source-downloads"
            build_downloads = work / "build-downloads"
            for directory in (binary_downloads, source_downloads, build_downloads):
                directory.mkdir()
            _download_lock(
                selected_python,
                BINARY_LOCK,
                binary_downloads,
                binary=True,
                windows_target=True,
            )
            _download_sources(source_downloads)
            _download_lock(
                selected_python,
                BUILD_LOCK,
                build_downloads,
                binary=True,
                windows_target=False,
            )
            built = _build_sources(
                selected_python,
                binary_downloads,
                build_downloads,
                source_downloads,
                work,
            )
            staging = target.parent / f".{target.name}.{os.urandom(8).hex()}.tmp"
            try:
                staging.mkdir()
                for source in sorted([*binary_downloads.glob("*.whl"), *built.glob("*.whl")]):
                    destination = staging / source.name
                    if destination.exists():
                        raise WheelhouseBuildError(f"duplicate wheelhouse filename: {source.name}")
                    shutil.copyfile(source, destination)
                if not any(staging.iterdir()):
                    raise WheelhouseBuildError("wheelhouse is empty")
                validate_committed_worker_wheelhouse(staging)
                os.replace(staging, target)
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the hash-locked CPython 3.11 win_amd64 Worker wheelhouse."
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    print(build_worker_wheelhouse(arguments.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
