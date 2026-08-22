"""Local credentials and short sessions for scoped API Service principals.

Service keys are deliberately separate from User root keys, Device keys and
Worker credentials.  The Gateway only receives the public half; private keys
live in the operating-system keyring or in an explicitly requested 0600 file.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import keyring

from vgen.crypto import (
    DeviceKeys,
    b64url_encode,
    deserialize_device_keys,
    serialize_device_keys,
)


class SecretBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class ServiceCredentialError(ValueError):
    """A credential failure whose message is safe to print."""


@dataclass(frozen=True, slots=True)
class ServiceCredentials:
    """Stable Service identity; short-lived session tokens are stored elsewhere."""

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
            raise ServiceCredentialError("Service ID, Workspace ID and Enrollment ID are required.")
        if not self.name:
            raise ServiceCredentialError("Service name is required.")
        if not self.scopes or any(not scope for scope in self.scopes):
            raise ServiceCredentialError("Service scopes are required.")

    @classmethod
    def generate(
        cls,
        *,
        service_id: str,
        workspace_id: str,
        name: str,
        scopes: list[str] | tuple[str, ...],
        enrollment_id: str,
        device_keys: DeviceKeys | None = None,
    ) -> ServiceCredentials:
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

    def to_bytes(self) -> bytes:
        return (
            json.dumps(
                {
                    "format": self.FORMAT,
                    "version": self.VERSION,
                    **{
                        key: value
                        for key, value in self.public_info().items()
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
                raise ServiceCredentialError("Service credential data must be an object.")
            if raw.get("format") != cls.FORMAT or raw.get("version") != cls.VERSION:
                raise ServiceCredentialError("Unsupported Service credential format.")
            scopes = raw["scopes"]
            if not isinstance(scopes, list) or not all(isinstance(item, str) for item in scopes):
                raise ServiceCredentialError("Service credential scopes are invalid.")
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
        except ServiceCredentialError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ServiceCredentialError("Invalid Service credential data.") from exc


class ServiceCredentialStore:
    """OS-keyring-first Service identity storage with a private-file alternative."""

    SERVICE = "vgen.service.credentials.v1"

    def __init__(self, backend: SecretBackend | None = None) -> None:
        self.backend = backend or keyring

    def save(
        self,
        account: str,
        credentials: ServiceCredentials,
        *,
        file_path: Path | None = None,
        overwrite: bool = False,
    ) -> None:
        if file_path is not None:
            _save_private_file(file_path, credentials.to_bytes(), overwrite=overwrite)
            return
        if not account:
            raise ServiceCredentialError("Service credential keyring account is required.")
        try:
            if not overwrite and self.backend.get_password(self.SERVICE, account) is not None:
                raise ServiceCredentialError(
                    "Service credentials already exist in the keyring account."
                )
            self.backend.set_password(self.SERVICE, account, credentials.to_bytes().decode("utf-8"))
        except ServiceCredentialError:
            raise
        except Exception as exc:
            raise ServiceCredentialError("The operating-system keyring is unavailable.") from exc

    def load(self, account: str, *, file_path: Path | None = None) -> ServiceCredentials:
        if file_path is not None:
            try:
                return ServiceCredentials.from_bytes(_read_private_file(file_path))
            except ServiceCredentialError:
                raise
            except OSError as exc:
                raise ServiceCredentialError("Service credential file cannot be read.") from exc
        if not account:
            raise ServiceCredentialError("Service credential keyring account is required.")
        try:
            value = self.backend.get_password(self.SERVICE, account)
        except Exception as exc:
            raise ServiceCredentialError("The operating-system keyring is unavailable.") from exc
        if value is None:
            raise ServiceCredentialError("No Service credentials exist in the keyring account.")
        return ServiceCredentials.from_bytes(value.encode("utf-8"))

    def delete(self, account: str, *, file_path: Path | None = None) -> None:
        if file_path is not None:
            resolved = _require_private_file(file_path)
            try:
                resolved.unlink()
            except OSError as exc:
                raise ServiceCredentialError("Service credential file cannot be removed.") from exc
            return
        if not account:
            raise ServiceCredentialError("Service credential keyring account is required.")
        try:
            self.backend.delete_password(self.SERVICE, account)
        except Exception as exc:
            raise ServiceCredentialError("The operating-system keyring is unavailable.") from exc


@dataclass(frozen=True, slots=True)
class StoredServiceSession:
    token: str = field(repr=False)
    expires_at: float
    service_id: str

    @property
    def expired(self) -> bool:
        return self.expires_at <= time.time() + 5


class ServiceSessionStore:
    """Service sessions use a different keyring namespace from User Device sessions."""

    SERVICE = "vgen.service.session.v1"

    def __init__(self, backend: SecretBackend | None = None) -> None:
        self.backend = backend or keyring

    @staticmethod
    def _account(profile_name: str, service_id: str) -> str:
        if not profile_name or not service_id:
            raise ServiceCredentialError("Profile name and Service ID are required.")
        return f"{profile_name}:{service_id}"

    def load(self, profile_name: str, service_id: str) -> StoredServiceSession | None:
        account = self._account(profile_name, service_id)
        try:
            encoded = self.backend.get_password(self.SERVICE, account)
        except Exception as exc:
            raise ServiceCredentialError("The operating-system keyring is unavailable.") from exc
        if not encoded:
            return None
        try:
            raw = json.loads(encoded)
            session = StoredServiceSession(
                token=str(raw["token"]),
                expires_at=float(raw["expires_at"]),
                service_id=str(raw["service_id"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.delete(profile_name, service_id)
            return None
        if session.service_id != service_id or session.expired:
            self.delete(profile_name, service_id)
            return None
        return session

    def save(self, profile_name: str, session: StoredServiceSession) -> None:
        try:
            self.backend.set_password(
                self.SERVICE,
                self._account(profile_name, session.service_id),
                json.dumps(
                    {
                        "token": session.token,
                        "expires_at": session.expires_at,
                        "service_id": session.service_id,
                    },
                    separators=(",", ":"),
                ),
            )
        except Exception as exc:
            raise ServiceCredentialError("The operating-system keyring is unavailable.") from exc

    def delete(self, profile_name: str, service_id: str) -> None:
        try:
            self.backend.delete_password(self.SERVICE, self._account(profile_name, service_id))
        except Exception:
            # Keyring backends differ on how a missing entry is reported.
            return


def _require_private_file(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ServiceCredentialError("Private Service files must not be symbolic links.")
    resolved = expanded.resolve()
    try:
        file_stat = resolved.stat()
    except OSError as exc:
        raise ServiceCredentialError("Service credential file cannot be read.") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise ServiceCredentialError("Service credential path must be a regular file.")
    if os.name != "nt" and stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise ServiceCredentialError("Service credential file must have mode 0600.")
    return resolved


def _read_private_file(path: Path) -> bytes:
    """Open the final path component with O_NOFOLLOW where the OS supports it."""

    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ServiceCredentialError("Private Service files must not be symbolic links.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(expanded, flags)
        with os.fdopen(descriptor, "rb") as stream:
            file_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise ServiceCredentialError("Service credential path must be a regular file.")
            if os.name != "nt" and stat.S_IMODE(file_stat.st_mode) & 0o077:
                raise ServiceCredentialError("Service credential file must have mode 0600.")
            return stream.read()
    except ServiceCredentialError:
        raise
    except OSError as exc:
        raise ServiceCredentialError("Service credential file cannot be read.") from exc


def _save_private_file(path: Path, value: bytes, *, overwrite: bool) -> None:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ServiceCredentialError("Private Service files must not be symbolic links.")
    parent = expanded.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    target = parent / expanded.name
    if target.exists() and not overwrite:
        raise ServiceCredentialError("Private Service file already exists.")
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
        raise ServiceCredentialError("Private Service file could not be written.") from exc
