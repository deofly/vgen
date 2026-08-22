from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import keyring
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vgen.crypto import (
    DeviceCertificate,
    DeviceKeys,
    IdentityBundle,
    IdentityKeys,
    b64url_decode,
    b64url_encode,
    identity_init,
    identity_recover,
    identity_recover_file,
    issue_device_certificate,
)
from vgen.protocol import new_id


class SecretBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class IdentityStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceIdentity:
    alias: str
    root_key_id: str
    root_signing_public_key: str
    root_encryption_public_key: str
    root_keys: IdentityKeys
    device_id: str
    device_keys: DeviceKeys
    certificate: DeviceCertificate

    def public_registration(self) -> dict[str, Any]:
        return {
            "root_key_id": self.root_key_id,
            "root_signing_public_key": self.root_signing_public_key,
            "root_encryption_public_key": self.root_encryption_public_key,
            "device_id": self.device_id,
            "device_certificate": self.certificate.to_dict(),
        }


class DeviceIdentityStore:
    SERVICE = "vgen.identity.v1"

    def __init__(self, backend: SecretBackend | None = None) -> None:
        self.backend = backend or keyring

    def initialize(
        self,
        alias: str = "default",
        *,
        overwrite: bool = False,
    ) -> tuple[IdentityBundle, DeviceIdentity]:
        bundle = identity_init()
        return bundle, self._create_device(alias, bundle.keys, overwrite=overwrite)

    def exists(self, alias: str = "default") -> bool:
        """Return whether an identity alias exists without exposing its value."""

        try:
            return self.backend.get_password(self.SERVICE, alias) is not None
        except Exception as exc:
            raise IdentityStoreError(f"OS keychain is unavailable: {type(exc).__name__}") from exc

    def recover_mnemonic(
        self,
        mnemonic: str,
        alias: str = "default",
        *,
        overwrite: bool = False,
    ) -> DeviceIdentity:
        return self._create_device(
            alias,
            identity_recover(mnemonic),
            overwrite=overwrite,
        )

    def recover_file(
        self,
        data: bytes,
        alias: str = "default",
        *,
        overwrite: bool = False,
    ) -> DeviceIdentity:
        return self._create_device(
            alias,
            identity_recover_file(data),
            overwrite=overwrite,
        )

    def load(self, alias: str = "default") -> DeviceIdentity:
        try:
            encoded = self.backend.get_password(self.SERVICE, alias)
        except Exception as exc:
            raise IdentityStoreError(f"OS keychain is unavailable: {type(exc).__name__}") from exc
        if not encoded:
            raise IdentityStoreError(f"identity does not exist in OS keychain: {alias}")
        try:
            raw = json.loads(encoded)
            device_keys = DeviceKeys(
                Ed25519PrivateKey.from_private_bytes(
                    b64url_decode(raw["device_signing_private_key"], expected_length=32)
                ),
                X25519PrivateKey.from_private_bytes(
                    b64url_decode(raw["device_encryption_private_key"], expected_length=32)
                ),
            )
            return DeviceIdentity(
                alias=alias,
                root_key_id=raw["root_key_id"],
                root_signing_public_key=raw["root_signing_public_key"],
                root_encryption_public_key=raw["root_encryption_public_key"],
                root_keys=IdentityKeys(
                    signing_private_key=Ed25519PrivateKey.from_private_bytes(
                        b64url_decode(raw["root_signing_private_key"], expected_length=32)
                    ),
                    encryption_private_key=X25519PrivateKey.from_private_bytes(
                        b64url_decode(raw["root_encryption_private_key"], expected_length=32)
                    ),
                ),
                device_id=raw["device_id"],
                device_keys=device_keys,
                certificate=DeviceCertificate.from_dict(raw["device_certificate"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IdentityStoreError("stored identity is corrupt") from exc

    def delete(self, alias: str = "default") -> None:
        try:
            self.backend.delete_password(self.SERVICE, alias)
        except Exception as exc:
            raise IdentityStoreError(
                f"cannot remove keychain identity: {type(exc).__name__}"
            ) from exc

    def _create_device(
        self,
        alias: str,
        keys: IdentityKeys,
        *,
        overwrite: bool,
    ) -> DeviceIdentity:
        try:
            existing = self.backend.get_password(self.SERVICE, alias)
        except Exception as exc:
            raise IdentityStoreError(f"OS keychain is unavailable: {type(exc).__name__}") from exc
        if existing is not None and not overwrite:
            raise IdentityStoreError(
                f"identity already exists in OS keychain: {alias}; use --overwrite explicitly"
            )
        device_id = new_id("device")
        device_keys = DeviceKeys.generate()
        certificate = issue_device_certificate(keys, device_keys, device_id=device_id)
        identity = DeviceIdentity(
            alias=alias,
            root_key_id=keys.root_key_id,
            root_signing_public_key=b64url_encode(keys.signing_public_bytes()),
            root_encryption_public_key=b64url_encode(keys.encryption_public_bytes()),
            root_keys=keys,
            device_id=device_id,
            device_keys=device_keys,
            certificate=certificate,
        )
        record = {
            "version": 1,
            "root_key_id": identity.root_key_id,
            "root_signing_public_key": identity.root_signing_public_key,
            "root_encryption_public_key": identity.root_encryption_public_key,
            "root_signing_private_key": b64url_encode(keys.signing_private_bytes()),
            "root_encryption_private_key": b64url_encode(keys.encryption_private_bytes()),
            "device_id": identity.device_id,
            "device_signing_private_key": b64url_encode(device_keys.signing_private_bytes()),
            "device_encryption_private_key": b64url_encode(device_keys.encryption_private_bytes()),
            "device_certificate": certificate.to_dict(),
        }
        try:
            self.backend.set_password(
                self.SERVICE,
                alias,
                json.dumps(record, separators=(",", ":")),
            )
        except Exception as exc:
            raise IdentityStoreError(
                f"cannot save identity in OS keychain: {type(exc).__name__}"
            ) from exc
        return identity
