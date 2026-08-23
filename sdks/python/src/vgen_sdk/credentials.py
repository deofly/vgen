"""Portable VGen API Service credentials with safe private-file helpers."""

from __future__ import annotations

import json
import os
import secrets
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .encoding import b64url_encode
from .errors import CredentialError
from .keys import DeviceKeys, deserialize_device_keys, serialize_device_keys

_MAX_CREDENTIAL_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class ServiceCredentials:
    """Long-lived API Service identity, separate from CLI user credentials."""

    service_id: str
    workspace_id: str
    name: str
    scopes: tuple[str, ...]
    enrollment_id: str
    device_keys: DeviceKeys = field(repr=False)

    FORMAT = "vgen-service-credentials"
    VERSION = 1

    def __post_init__(self) -> None:
        if not self.service_id or not self.workspace_id or not self.enrollment_id:
            raise CredentialError("Service ID, Workspace ID and Enrollment ID are required.")
        if not self.name:
            raise CredentialError("Service name is required.")
        if not self.scopes or any(not isinstance(scope, str) or not scope for scope in self.scopes):
            raise CredentialError("Service scopes are required.")

    @classmethod
    def generate(
        cls,
        *,
        service_id: str,
        workspace_id: str,
        name: str,
        scopes: Sequence[str],
        enrollment_id: str,
        device_keys: DeviceKeys | None = None,
    ) -> ServiceCredentials:
        if isinstance(scopes, str):
            raise CredentialError("Service scopes must be a sequence of scope strings.")
        return cls(
            service_id=service_id,
            workspace_id=workspace_id,
            name=name,
            scopes=tuple(sorted(set(scopes))),
            enrollment_id=enrollment_id,
            device_keys=device_keys or DeviceKeys.generate(),
        )

    def public_info(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "workspace_id": self.workspace_id,
            "name": self.name,
            "scopes": list(self.scopes),
            "enrollment_id": self.enrollment_id,
            "key_id": self.device_keys.key_id,
            "signing_public_key": b64url_encode(self.device_keys.signing_public_bytes()),
            "encryption_public_key": b64url_encode(self.device_keys.encryption_public_bytes()),
        }

    @property
    def keys(self) -> DeviceKeys:
        """Return the Service keys (legacy wire field: ``device_keys``)."""

        return self.device_keys

    def to_bytes(self) -> bytes:
        """Serialize exactly as ``vgen-service-credentials`` version 1."""

        public = self.public_info()
        return (
            json.dumps(
                {
                    "format": self.FORMAT,
                    "version": self.VERSION,
                    **{
                        key: value
                        for key, value in public.items()
                        if key not in {"key_id", "signing_public_key", "encryption_public_key"}
                    },
                    "device_keys": json.loads(serialize_device_keys(self.device_keys)),
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> ServiceCredentials:
        try:
            raw: Any = json.loads(value.decode("utf-8"))
            if not isinstance(raw, dict):
                raise CredentialError("Service credential data must be an object.")
            version = raw.get("version")
            if (
                raw.get("format") != cls.FORMAT
                or not isinstance(version, int)
                or isinstance(version, bool)
                or version != cls.VERSION
            ):
                raise CredentialError("Unsupported Service credential format.")
            scopes = raw["scopes"]
            if not isinstance(scopes, list) or not all(isinstance(item, str) for item in scopes):
                raise CredentialError("Service credential scopes are invalid.")
            serialized_keys = json.dumps(
                raw["device_keys"],
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            return cls(
                service_id=str(raw["service_id"]),
                workspace_id=str(raw["workspace_id"]),
                name=str(raw["name"]),
                scopes=tuple(scopes),
                enrollment_id=str(raw["enrollment_id"]),
                device_keys=deserialize_device_keys(serialized_keys),
            )
        except CredentialError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CredentialError("Invalid Service credential data.") from exc

    @classmethod
    def load(cls, path: str | Path) -> ServiceCredentials:
        """Load a regular, non-symlink credential file (0600 on POSIX)."""

        return cls.from_bytes(_read_private_file(Path(path)))

    def save(self, path: str | Path, *, overwrite: bool = False) -> None:
        """Atomically save a credential file with private permissions."""

        _save_private_file(Path(path), self.to_bytes(), overwrite=overwrite)


def _read_private_file(path: Path) -> bytes:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise CredentialError("Private Service files must not be symbolic links.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(expanded, flags)
        with os.fdopen(descriptor, "rb") as stream:
            file_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise CredentialError("Service credential path must be a regular file.")
            if os.name != "nt" and stat.S_IMODE(file_stat.st_mode) != 0o600:
                raise CredentialError("Service credential file must have mode 0600.")
            if file_stat.st_size > _MAX_CREDENTIAL_BYTES:
                raise CredentialError("Service credential file is too large.")
            value = stream.read(_MAX_CREDENTIAL_BYTES + 1)
            if len(value) > _MAX_CREDENTIAL_BYTES:
                raise CredentialError("Service credential file is too large.")
            return value
    except CredentialError:
        raise
    except OSError as exc:
        raise CredentialError("Service credential file cannot be read.") from exc


def _require_private_file(path: Path) -> None:
    if path.is_symlink():
        raise CredentialError("Private Service files must not be symbolic links.")
    try:
        file_stat = path.stat()
    except OSError as exc:
        raise CredentialError("Service credential file cannot be read.") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise CredentialError("Service credential path must be a regular file.")
    if os.name != "nt" and stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise CredentialError("Service credential file must have mode 0600.")


def _save_private_file(path: Path, value: bytes, *, overwrite: bool) -> None:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise CredentialError("Private Service files must not be symbolic links.")
    parent = expanded.parent.resolve()
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CredentialError("Service credential directory could not be created.") from exc
    target = parent / expanded.name
    if target.exists() and not overwrite:
        raise CredentialError("Private Service file already exists.")
    if target.exists():
        _require_private_file(target)
    temporary = parent / f".{target.name}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, target)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        raise CredentialError("Private Service file could not be written.") from exc
