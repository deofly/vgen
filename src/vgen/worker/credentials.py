"""Local Worker identity and short-lived session storage.

The Gateway only knows Worker public keys. The corresponding Ed25519/X25519
private keys stay either in the operating-system keyring or in an explicitly
permissioned local file. Secret values never appear in exceptions or reprs.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vgen.crypto import (
    DeviceKeys,
    b64url_decode,
    b64url_encode,
    deserialize_device_keys,
    serialize_device_keys,
)

KEYRING_SERVICE = "vgen.worker.v1"
_FORMAT = "vgen-worker-credentials"
_VERSION = 1
_IDENTITY_FORMAT = "vgen-worker-identity"


class WorkerCredentialError(ValueError):
    """A safe local credential configuration error."""


@dataclass(frozen=True, slots=True)
class WorkerCredentials:
    worker_id: str
    device_keys: DeviceKeys = field(repr=False)
    session_token: str = field(repr=False)
    # This is the local trust anchor for Broker-issued maintenance intents.  It
    # is public, but it travels with the private Worker credential bundle so a
    # compromised Gateway cannot substitute another Worker owner's root key.
    owner_root_signing_public_key: str | None = None

    def __post_init__(self) -> None:
        if not self.worker_id:
            raise WorkerCredentialError("Worker ID is required.")
        if not self.session_token:
            raise WorkerCredentialError("Worker session token is required.")
        if self.owner_root_signing_public_key is not None:
            try:
                b64url_decode(self.owner_root_signing_public_key, expected_length=32)
            except (TypeError, ValueError) as exc:
                raise WorkerCredentialError(
                    "Worker owner root signing public key is invalid."
                ) from exc

    def to_bytes(self) -> bytes:
        return (
            json.dumps(
                {
                    "format": _FORMAT,
                    "version": _VERSION,
                    "worker_id": self.worker_id,
                    "device_keys": json.loads(serialize_device_keys(self.device_keys)),
                    "session_token": self.session_token,
                    **(
                        {"owner_root_signing_public_key": (self.owner_root_signing_public_key)}
                        if self.owner_root_signing_public_key is not None
                        else {}
                    ),
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> WorkerCredentials:
        try:
            decoded: Any = json.loads(value.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise WorkerCredentialError("Worker credential data must be an object.")
            if decoded.get("format") != _FORMAT or decoded.get("version") != _VERSION:
                raise WorkerCredentialError("Unsupported Worker credential format.")
            serialized_keys = json.dumps(
                decoded["device_keys"],
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            return cls(
                worker_id=str(decoded["worker_id"]),
                device_keys=deserialize_device_keys(serialized_keys),
                session_token=str(decoded["session_token"]),
                owner_root_signing_public_key=(
                    None
                    if decoded.get("owner_root_signing_public_key") is None
                    else str(decoded["owner_root_signing_public_key"])
                ),
            )
        except WorkerCredentialError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkerCredentialError("Invalid Worker credential data.") from exc


@dataclass(frozen=True, slots=True)
class WorkerIdentity:
    """Stable random Worker signing/encryption keys, independent of sessions."""

    device_keys: DeviceKeys = field(repr=False)

    @classmethod
    def generate(cls) -> WorkerIdentity:
        return cls(DeviceKeys.generate())

    @property
    def key_id(self) -> str:
        return self.device_keys.key_id

    def to_bytes(self) -> bytes:
        return (
            json.dumps(
                {
                    "format": _IDENTITY_FORMAT,
                    "version": _VERSION,
                    "device_keys": json.loads(serialize_device_keys(self.device_keys)),
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> WorkerIdentity:
        try:
            decoded: Any = json.loads(value.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise WorkerCredentialError("Worker identity data must be an object.")
            if decoded.get("format") != _IDENTITY_FORMAT or decoded.get("version") != _VERSION:
                raise WorkerCredentialError("Unsupported Worker identity format.")
            serialized_keys = json.dumps(
                decoded["device_keys"],
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            return cls(deserialize_device_keys(serialized_keys))
        except WorkerCredentialError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkerCredentialError("Invalid Worker identity data.") from exc

    def public_registration(
        self,
        *,
        name: str,
        executor_type: str,
        executor_version: str = "",
        capabilities: dict[str, Any] | None = None,
        manager_broker_id: str | None = None,
        capacity: int = 1,
        certificate: str | None = None,
    ) -> dict[str, Any]:
        """Build the public body accepted by ``POST /api/v1/workers``."""

        if not name or not executor_type:
            raise WorkerCredentialError("Worker name and executor type are required.")
        if capacity < 1:
            raise WorkerCredentialError("Worker capacity must be positive.")
        value = {
            "name": name,
            "manager_broker_id": manager_broker_id,
            "signing_public_key": b64url_encode(self.device_keys.signing_public_bytes()),
            "encryption_public_key": b64url_encode(self.device_keys.encryption_public_bytes()),
            "executor_type": executor_type,
            "executor_version": executor_version,
            "capabilities": dict(capabilities or {}),
            "capacity": capacity,
        }
        if certificate is not None:
            value["certificate"] = certificate
        return value

    def public_info(self) -> dict[str, str]:
        return {
            "key_id": self.key_id,
            "signing_public_key": b64url_encode(self.device_keys.signing_public_bytes()),
            "encryption_public_key": b64url_encode(self.device_keys.encryption_public_bytes()),
        }


class WorkerIdentityStore:
    """OS-keyring-first storage with an explicit 0600 file alternative."""

    def __init__(self, *, service: str = KEYRING_SERVICE + ".identity") -> None:
        self._service = service

    def generate(
        self,
        account: str,
        *,
        file_path: Path | None = None,
        overwrite: bool = False,
    ) -> WorkerIdentity:
        identity = WorkerIdentity.generate()
        self.save(account, identity, file_path=file_path, overwrite=overwrite)
        return identity

    def load(self, account: str, *, file_path: Path | None = None) -> WorkerIdentity:
        if file_path is not None:
            resolved = _require_private_file(file_path)
            try:
                return WorkerIdentity.from_bytes(resolved.read_bytes())
            except WorkerCredentialError:
                raise
            except OSError as exc:
                raise WorkerCredentialError("Worker identity file cannot be read.") from exc
        if not account:
            raise WorkerCredentialError("Worker identity keyring account is required.")
        try:
            import keyring
            from keyring.errors import KeyringError

            value = keyring.get_password(self._service, account)
        except (ImportError, KeyringError) as exc:
            raise WorkerCredentialError("The operating-system keyring is unavailable.") from exc
        if value is None:
            raise WorkerCredentialError("No Worker identity exists in the keyring.")
        return WorkerIdentity.from_bytes(value.encode("utf-8"))

    def save(
        self,
        account: str,
        identity: WorkerIdentity,
        *,
        file_path: Path | None = None,
        overwrite: bool = False,
    ) -> None:
        if file_path is not None:
            _save_private_bytes(file_path, identity.to_bytes(), overwrite=overwrite)
            return
        if not account:
            raise WorkerCredentialError("Worker identity keyring account is required.")
        try:
            import keyring
            from keyring.errors import KeyringError

            if not overwrite and keyring.get_password(self._service, account) is not None:
                raise WorkerCredentialError("Worker identity already exists in the keyring.")
            keyring.set_password(self._service, account, identity.to_bytes().decode("utf-8"))
        except WorkerCredentialError:
            raise
        except (ImportError, KeyringError) as exc:
            raise WorkerCredentialError("The operating-system keyring is unavailable.") from exc


def _require_private_file(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise WorkerCredentialError("Private Worker files must not be symbolic links.")
    resolved = expanded.resolve()
    try:
        file_stat = resolved.stat()
    except OSError as exc:
        raise WorkerCredentialError("Worker credential file cannot be read.") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise WorkerCredentialError("Worker credential path must be a regular file.")
    if os.name != "nt" and stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise WorkerCredentialError("Worker credential file must have mode 0600.")
    return resolved


def load_worker_credentials_file(path: Path) -> WorkerCredentials:
    resolved = _require_private_file(path)
    try:
        return WorkerCredentials.from_bytes(resolved.read_bytes())
    except WorkerCredentialError:
        raise
    except OSError as exc:
        raise WorkerCredentialError("Worker credential file cannot be read.") from exc


def save_worker_credentials_file(
    path: Path,
    credentials: WorkerCredentials,
    *,
    overwrite: bool = False,
) -> None:
    """Write a recoverable 0600 credential file without following symlinks."""

    _save_private_bytes(path, credentials.to_bytes(), overwrite=overwrite)


def _save_private_bytes(path: Path, value: bytes, *, overwrite: bool) -> None:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise WorkerCredentialError("Private Worker files must not be symbolic links.")
    parent = expanded.parent.resolve()
    resolved = parent / expanded.name
    resolved.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
        if os.name == "nt":
            try:
                _protect_windows_private_file(resolved)
            except WorkerCredentialError:
                # A private key with inherited or unknown ACLs must never be
                # left behind after a failed hardening attempt.
                try:
                    resolved.unlink()
                except OSError:
                    pass
                raise
        else:
            resolved.chmod(0o600)
    except FileExistsError as exc:
        raise WorkerCredentialError("Private Worker file already exists.") from exc
    except OSError as exc:
        raise WorkerCredentialError("Private Worker file could not be written.") from exc


def _protect_windows_private_file(path: Path) -> None:
    """Replace inherited ACLs with the current user and LocalSystem only.

    Python's POSIX mode argument does not protect a file on Windows.  ``icacls``
    is present on supported Windows editions and accepts SID notation, avoiding
    localized account-name ambiguity.  Any inability to determine or apply the
    ACL is fatal and the caller removes the newly written credential file.
    """

    try:
        identity = subprocess.run(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        # The stable CSV shape is "DOMAIN\\name","S-1-...".  Use the CSV
        # parser rather than including either localized account name in an
        # access-control command.
        import csv
        import io

        records = list(csv.reader(io.StringIO(identity.stdout)))
        sid = records[0][1].strip() if len(records) == 1 and len(records[0]) >= 2 else ""
        if not sid.startswith("S-1-"):
            raise ValueError
        hardened = subprocess.run(
            [
                "icacls.exe",
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(F)",
                "*S-1-5-18:(F)",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if hardened.returncode != 0:
            raise ValueError
        verified = subprocess.run(
            ["icacls.exe", str(path), "/verify"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if verified.returncode != 0:
            raise ValueError
    except (IndexError, OSError, subprocess.SubprocessError, ValueError) as exc:
        raise WorkerCredentialError(
            "Windows could not apply private Worker credential access rules."
        ) from exc


def load_worker_credentials_keyring(worker_id: str) -> WorkerCredentials:
    if not worker_id:
        raise WorkerCredentialError("Worker ID is required for keyring lookup.")
    try:
        import keyring
        from keyring.errors import KeyringError

        value = keyring.get_password(KEYRING_SERVICE, worker_id)
    except (ImportError, KeyringError) as exc:
        raise WorkerCredentialError("The operating-system keyring is unavailable.") from exc
    if value is None:
        raise WorkerCredentialError("No Worker credentials exist in the keyring.")
    credentials = WorkerCredentials.from_bytes(value.encode("utf-8"))
    if credentials.worker_id != worker_id:
        raise WorkerCredentialError("Worker keyring entry does not match the requested Worker ID.")
    return credentials


def save_worker_credentials_keyring(credentials: WorkerCredentials) -> None:
    try:
        import keyring
        from keyring.errors import KeyringError

        keyring.set_password(
            KEYRING_SERVICE,
            credentials.worker_id,
            credentials.to_bytes().decode("utf-8"),
        )
    except (ImportError, KeyringError) as exc:
        raise WorkerCredentialError("The operating-system keyring is unavailable.") from exc
