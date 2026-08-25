"""Fail-closed, resumable installation of locally authorized model files."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import os
import re
import shutil
import socket
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

import requests


class ModelInstallError(RuntimeError):
    """A bounded maintenance error which never embeds a source URL or token."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class ModelPin(Protocol):
    path: str
    sha256: str
    size: int
    source: str | None
    revision: str | None
    license: str | None
    license_url: str | None
    gated: bool
    manual_download: bool


@dataclass(frozen=True, slots=True)
class ModelInstallResult:
    digest: str
    status: str
    size: int


ProgressCallback = Callable[[int, int], None]
Resolver = Callable[[str, int], Iterable[str]]

_CONTENT_RANGE = re.compile(r"^bytes (?P<start>\d+)-(?P<end>\d+)/(?P<total>\d+)$")
_MAX_REDIRECTS = 8
_CHUNK_SIZE = 8 * 1024 * 1024
_DISK_SAFETY_BYTES = 64 * 1024 * 1024
_HF_TOKEN_MAX_BYTES = 4096


def _default_resolver(host: str, port: int) -> tuple[str, ...]:
    try:
        values = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ModelInstallError("MODEL_SOURCE_UNAVAILABLE", retryable=True) from exc
    return tuple(dict.fromkeys(str(item[4][0]) for item in values))


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while block := stream.read(_CHUNK_SIZE):
                size += len(block)
                digest.update(block)
    except OSError as exc:
        raise ModelInstallError("MODEL_FILE_UNREADABLE") from exc
    return size, digest.hexdigest()


class ModelInstaller:
    """Download a policy pin without accepting a remote destination or digest.

    Sources come exclusively from the local machine-admin policy.  Every URL and
    redirect must resolve only to public addresses, and a target is published by
    creating a hard link.  The latter is an atomic create-if-absent operation on
    both Windows and POSIX, so a raced or pre-existing model is never replaced.
    """

    def __init__(
        self,
        model_root: Path,
        *,
        session: requests.Session | None = None,
        resolver: Resolver = _default_resolver,
        timeout: tuple[float, float] = (15.0, 300.0),
        huggingface_token: str | None = None,
    ) -> None:
        raw_root = model_root.expanduser()
        if raw_root.is_symlink():
            raise ModelInstallError("MODEL_ROOT_UNSAFE")
        try:
            self._root = raw_root.resolve(strict=True)
        except OSError as exc:
            raise ModelInstallError("MODEL_ROOT_UNAVAILABLE") from exc
        if not self._root.is_dir() or _is_reparse_point(self._root):
            raise ModelInstallError("MODEL_ROOT_UNSAFE")
        self._session = session or requests.Session()
        self._resolver = resolver
        self._timeout = timeout
        self._huggingface_token = (
            _validate_huggingface_token(huggingface_token)
            if huggingface_token is not None
            else None
        )
        # A malformed optional Hugging Face token must not make ordinary,
        # public model installs fail.  Read the Worker-local credential only
        # when a gated pin actually needs it.
        self._load_default_huggingface_token = huggingface_token is None

    def install(
        self,
        pin: ModelPin,
        *,
        progress: ProgressCallback | None = None,
    ) -> ModelInstallResult:
        digest = str(pin.sha256).removeprefix("sha256:").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not 1 <= int(pin.size) <= 1024**5:
            raise ModelInstallError("MODEL_PIN_INVALID")
        target = self._safe_target(pin.path)
        blob = self._blob_path(digest)
        if _is_reparse_point(target):
            raise ModelInstallError("MODEL_TARGET_CONFLICT")
        if target.exists():
            self._assert_regular_target(target)
            size, actual = _hash_file(target)
            if size == pin.size and actual == digest:
                self._make_read_only(target)
                self._publish_blob(target, blob, pin.size, digest)
                return ModelInstallResult(f"sha256:{digest}", "already_installed", size)
            raise ModelInstallError("MODEL_TARGET_CONFLICT")

        if blob.exists():
            self._assert_regular_target(blob)
            self._make_read_only(blob)
            if _hash_file(blob) != (pin.size, digest):
                raise ModelInstallError("MODEL_CACHE_CONFLICT")
            self._link_target(blob, target, pin.size, digest)
            return ModelInstallResult(f"sha256:{digest}", "already_installed", pin.size)

        partial = target.with_name(f".{target.name}.{digest[:16]}.vgen.partial")
        self._assert_partial(partial, maximum=pin.size)
        partial_size = partial.stat().st_size if partial.exists() else 0
        if partial_size == pin.size:
            if _hash_file(partial) == (pin.size, digest):
                self._publish_blob(partial, blob, pin.size, digest)
                try:
                    partial.unlink(missing_ok=True)
                except OSError:
                    pass
                self._make_read_only(blob)
                self._link_target(blob, target, pin.size, digest)
                return ModelInstallResult(f"sha256:{digest}", "installed", pin.size)
            try:
                partial.unlink()
            except OSError as exc:
                raise ModelInstallError("MODEL_FILE_UNREADABLE") from exc
            partial_size = 0

        # Download policy and credentials are needed only on a local cache miss.
        # A digest-verified target, CAS blob, or completed resumable partial is
        # safe to reuse even when its original source is gated or manual-only.
        source = pin.source
        if pin.manual_download:
            raise ModelInstallError("MODEL_MANUAL_ACTION_REQUIRED")
        if not source:
            raise ModelInstallError("MODEL_SOURCE_UNAVAILABLE")
        if pin.gated:
            try:
                source_host = urlsplit(source).hostname
            except ValueError as exc:
                raise ModelInstallError("MODEL_SOURCE_INVALID") from exc
            if source_host != "huggingface.co":
                raise ModelInstallError("MODEL_GATED_SOURCE_INVALID")
            if self._huggingface_token is None and self._load_default_huggingface_token:
                self._huggingface_token = _load_huggingface_token()
                self._load_default_huggingface_token = False
            if self._huggingface_token is None:
                raise ModelInstallError("MODEL_GATED_CREDENTIAL_UNAVAILABLE")
        remaining = pin.size - partial_size
        try:
            free = shutil.disk_usage(target.parent).free
        except OSError as exc:
            raise ModelInstallError("MODEL_DISK_UNAVAILABLE", retryable=True) from exc
        if free < remaining + min(_DISK_SAFETY_BYTES, max(pin.size // 100, 1)):
            raise ModelInstallError("MODEL_DISK_FULL")

        response = self._open_public_download(source, offset=partial_size)
        try:
            if partial_size and response.status_code == 200:
                # The origin ignored Range. This file name is digest-derived and
                # was proven regular, so truncating our own partial is safe.
                partial_size = 0
            elif response.status_code == 206:
                content_range = response.headers.get("Content-Range", "")
                match = _CONTENT_RANGE.fullmatch(content_range)
                if (
                    match is None
                    or int(match.group("start")) != partial_size
                    or int(match.group("total")) != pin.size
                ):
                    raise ModelInstallError("MODEL_RANGE_INVALID", retryable=True)
            elif response.status_code != 200:
                raise ModelInstallError(
                    "MODEL_SOURCE_UNAVAILABLE", retryable=response.status_code >= 500
                )

            mode = "ab" if partial_size else "wb"
            consumed = partial_size
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                self._assert_safe_ancestry(target.parent)
                with partial.open(mode) as output:
                    for chunk in response.iter_content(chunk_size=_CHUNK_SIZE):
                        if not chunk:
                            continue
                        consumed += len(chunk)
                        if consumed > pin.size:
                            raise ModelInstallError("MODEL_SIZE_MISMATCH")
                        output.write(chunk)
                        if progress is not None:
                            progress(consumed, pin.size)
                    output.flush()
                    os.fsync(output.fileno())
            except ModelInstallError:
                raise
            except (OSError, requests.RequestException) as exc:
                raise ModelInstallError("MODEL_DOWNLOAD_FAILED", retryable=True) from exc
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

        size, actual = _hash_file(partial)
        if size != pin.size:
            raise ModelInstallError("MODEL_SIZE_MISMATCH", retryable=True)
        if actual != digest:
            # A complete-size corrupt partial would otherwise be resumed from
            # EOF forever (typically receiving HTTP 416).  Remove it so an
            # explicit retry starts from byte zero.
            try:
                partial.unlink(missing_ok=True)
            except OSError as exc:
                raise ModelInstallError("MODEL_FILE_UNREADABLE") from exc
            raise ModelInstallError("MODEL_INTEGRITY_FAILED")
        if target.exists():
            self._assert_regular_target(target)
            if _hash_file(target) == (pin.size, digest):
                self._make_read_only(target)
                self._publish_blob(target, blob, pin.size, digest)
                try:
                    partial.unlink(missing_ok=True)
                except OSError:
                    pass
                return ModelInstallResult(f"sha256:{digest}", "already_installed", pin.size)
            raise ModelInstallError("MODEL_TARGET_CONFLICT")
        self._publish_blob(partial, blob, pin.size, digest)
        try:
            partial.unlink(missing_ok=True)
        except OSError:
            pass
        self._make_read_only(blob)
        self._link_target(blob, target, pin.size, digest)
        return ModelInstallResult(f"sha256:{digest}", "installed", pin.size)

    def _blob_path(self, digest: str) -> Path:
        directory = self._root / ".vgen" / "artifacts" / "sha256" / digest[:2]
        self._assert_safe_ancestry(directory)
        blob = directory / digest
        if _is_reparse_point(blob):
            raise ModelInstallError("MODEL_CACHE_CONFLICT")
        return blob

    def _publish_blob(self, source: Path, blob: Path, size: int, digest: str) -> None:
        if blob.exists():
            self._assert_regular_target(blob)
            self._make_read_only(blob)
            if _hash_file(blob) != (size, digest):
                raise ModelInstallError("MODEL_CACHE_CONFLICT")
            return
        try:
            os.link(source, blob)
        except FileExistsError as exc:
            self._assert_regular_target(blob)
            self._make_read_only(blob)
            if _hash_file(blob) != (size, digest):
                raise ModelInstallError("MODEL_CACHE_CONFLICT") from exc
        except OSError as exc:
            if exc.errno in {errno.EPERM, errno.EACCES}:
                raise ModelInstallError("MODEL_CACHE_UNAVAILABLE") from exc
            raise ModelInstallError("MODEL_INSTALL_FAILED") from exc

    def _link_target(self, blob: Path, target: Path, size: int, digest: str) -> None:
        self._make_read_only(blob)
        created = False
        try:
            os.link(blob, target)
            created = True
        except FileExistsError as exc:
            self._assert_regular_target(target)
            if _hash_file(target) == (size, digest):
                self._make_read_only(target)
                return
            raise ModelInstallError("MODEL_TARGET_CONFLICT") from exc
        except OSError as exc:
            if exc.errno in {errno.EEXIST, errno.EPERM, errno.EACCES}:
                raise ModelInstallError("MODEL_TARGET_CONFLICT") from exc
            raise ModelInstallError("MODEL_INSTALL_FAILED") from exc
        try:
            self._make_read_only(target)
        except ModelInstallError:
            if created:
                try:
                    target.unlink(missing_ok=True)
                except OSError:
                    pass
            raise

    @staticmethod
    def _make_read_only(path: Path) -> None:
        """Remove write permissions from a shared model inode.

        An administrator can deliberately restore write access, so callers
        still hash every existing target/CAS blob before reuse.  The permission
        is a guard against accidental in-place writes, not a trust boundary.
        """

        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(path):
                raise ModelInstallError("MODEL_TARGET_CONFLICT")
            mode = stat.S_IMODE(metadata.st_mode)
            read_only_mode = stat.S_IREAD if os.name == "nt" else mode & ~0o222
            if mode != read_only_mode:
                path.chmod(read_only_mode)
            if stat.S_IMODE(path.lstat().st_mode) & 0o222:
                raise OSError("model artifact remains writable")
        except ModelInstallError:
            raise
        except OSError as exc:
            raise ModelInstallError("MODEL_PATH_UNAVAILABLE") from exc

    def _safe_target(self, relative: str) -> Path:
        if not isinstance(relative, str):
            raise ModelInstallError("MODEL_PATH_INVALID")
        normalized = relative.replace("\\", "/")
        posix = PurePosixPath(normalized)
        windows = PureWindowsPath(relative)
        if (
            not normalized
            or normalized.startswith("/")
            or windows.drive
            or windows.is_absolute()
            or any(part in {"", ".", ".."} for part in posix.parts)
            or any(character in normalized for character in ("\x00", "\r", "\n", ":"))
        ):
            raise ModelInstallError("MODEL_PATH_INVALID")
        target = self._root.joinpath(*posix.parts)
        self._assert_safe_ancestry(target.parent)
        return target

    def _assert_safe_ancestry(self, directory: Path) -> None:
        try:
            relative = directory.relative_to(self._root)
        except ValueError as exc:
            raise ModelInstallError("MODEL_PATH_INVALID") from exc
        current = self._root
        for part in relative.parts:
            current = current / part
            if current.exists() and (_is_reparse_point(current) or not current.is_dir()):
                raise ModelInstallError("MODEL_PATH_UNSAFE")
        # Create one component at a time, then recheck it. Avoid following a
        # concurrently substituted junction or symlink.
        current = self._root
        for part in relative.parts:
            current = current / part
            try:
                current.mkdir(exist_ok=True)
            except OSError as exc:
                raise ModelInstallError("MODEL_PATH_UNAVAILABLE") from exc
            if _is_reparse_point(current) or not current.is_dir():
                raise ModelInstallError("MODEL_PATH_UNSAFE")

    @staticmethod
    def _assert_regular_target(path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ModelInstallError("MODEL_FILE_UNREADABLE") from exc
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(path):
            raise ModelInstallError("MODEL_TARGET_CONFLICT")

    @staticmethod
    def _assert_partial(path: Path, *, maximum: int) -> None:
        if _is_reparse_point(path):
            raise ModelInstallError("MODEL_PARTIAL_UNSAFE")
        if not path.exists():
            return
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ModelInstallError("MODEL_PARTIAL_UNSAFE") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or _is_reparse_point(path)
            or metadata.st_size > maximum
        ):
            raise ModelInstallError("MODEL_PARTIAL_UNSAFE")

    def _open_public_download(self, source: str, *, offset: int) -> Any:
        current = source
        range_headers = {"Range": f"bytes={offset}-"} if offset else {}
        for _ in range(_MAX_REDIRECTS + 1):
            self._validate_public_url(current)
            parsed = urlsplit(current)
            headers = dict(range_headers)
            if parsed.hostname == "huggingface.co" and self._huggingface_token is not None:
                headers["Authorization"] = f"Bearer {self._huggingface_token}"
            try:
                response = self._session.request(
                    "GET",
                    current,
                    headers=headers,
                    stream=True,
                    allow_redirects=False,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                raise ModelInstallError("MODEL_SOURCE_UNAVAILABLE", retryable=True) from exc
            if response.status_code not in {301, 302, 303, 307, 308}:
                if response.status_code in {401, 403} and self._huggingface_token is not None:
                    raise ModelInstallError("MODEL_GATED_CREDENTIAL_REJECTED")
                return response
            location = response.headers.get("Location")
            close = getattr(response, "close", None)
            if callable(close):
                close()
            if not location:
                raise ModelInstallError("MODEL_REDIRECT_INVALID")
            current = urljoin(current, location)
        raise ModelInstallError("MODEL_REDIRECT_LIMIT")

    def _validate_public_url(self, value: str) -> None:
        try:
            parsed = urlsplit(value)
            port = parsed.port or 443
        except ValueError as exc:
            raise ModelInstallError("MODEL_SOURCE_INVALID") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or port != 443
        ):
            raise ModelInstallError("MODEL_SOURCE_INVALID")
        addresses = tuple(self._resolver(parsed.hostname, port))
        if not addresses:
            raise ModelInstallError("MODEL_SOURCE_UNAVAILABLE", retryable=True)
        try:
            if any(not ipaddress.ip_address(address).is_global for address in addresses):
                raise ModelInstallError("MODEL_SOURCE_NOT_PUBLIC")
        except ValueError as exc:
            raise ModelInstallError("MODEL_SOURCE_INVALID") from exc


def _validate_huggingface_token(value: str) -> str:
    token = value.strip()
    if (
        not token
        or len(token.encode("utf-8")) > _HF_TOKEN_MAX_BYTES
        or any(character.isspace() or ord(character) < 0x20 for character in token)
    ):
        raise ModelInstallError("MODEL_GATED_CREDENTIAL_INVALID")
    return token


def _load_huggingface_token() -> str | None:
    environment = os.environ.get("HF_TOKEN")
    if environment:
        return _validate_huggingface_token(environment)
    configured_path = os.environ.get("HF_TOKEN_PATH")
    if configured_path:
        candidates = (Path(configured_path).expanduser(),)
    else:
        hf_home = Path(os.environ.get("HF_HOME", str(Path.home() / ".cache" / "huggingface")))
        candidates = (hf_home.expanduser() / "token",)
    for candidate in candidates:
        if not candidate.exists():
            continue
        if candidate.is_symlink():
            raise ModelInstallError("MODEL_GATED_CREDENTIAL_INVALID")
        try:
            metadata = candidate.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ModelInstallError("MODEL_GATED_CREDENTIAL_INVALID")
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ModelInstallError("MODEL_GATED_CREDENTIAL_INVALID")
            return _validate_huggingface_token(
                candidate.read_text(encoding="utf-8", errors="strict")
            )
        except ModelInstallError:
            raise
        except (OSError, UnicodeError) as exc:
            raise ModelInstallError("MODEL_GATED_CREDENTIAL_INVALID") from exc
    return None


__all__ = ["ModelInstallError", "ModelInstallResult", "ModelInstaller", "ModelPin"]
