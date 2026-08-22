from __future__ import annotations

import keyring

from vgen.crypto import b64url_decode, b64url_encode, generate_workspace_data_key


class WorkspaceKeyError(RuntimeError):
    pass


class WorkspaceKeyStore:
    """Device-local cache of versioned Workspace Data Keys.

    Gateway persists only recipient envelopes. Broker/device synchronization is
    responsible for importing a key onto another authorized device.
    """

    SERVICE = "vgen.workspace-key.v1"

    def __init__(self, backend=None) -> None:  # type: ignore[no-untyped-def]
        self.backend = backend or keyring

    @staticmethod
    def _username(workspace_id: str, version: int) -> str:
        if not workspace_id or version < 1:
            raise ValueError("workspace ID and positive key version are required")
        return f"{workspace_id}:v{version}"

    def create(self, workspace_id: str, version: int = 1) -> bytes:
        key = generate_workspace_data_key()
        self.save(workspace_id, version, key)
        return key

    def save(self, workspace_id: str, version: int, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("Workspace Data Key must contain 32 bytes")
        self.backend.set_password(
            self.SERVICE,
            self._username(workspace_id, version),
            b64url_encode(key),
        )

    def load(self, workspace_id: str, version: int = 1) -> bytes:
        encoded = self.backend.get_password(self.SERVICE, self._username(workspace_id, version))
        if not encoded:
            raise WorkspaceKeyError(
                "Workspace key is unavailable on this device; import a key envelope with a Broker device"
            )
        try:
            return b64url_decode(encoded, expected_length=32)
        except ValueError as exc:
            raise WorkspaceKeyError("stored Workspace key is corrupt") from exc

    def delete(self, workspace_id: str, version: int = 1) -> None:
        try:
            self.backend.delete_password(self.SERVICE, self._username(workspace_id, version))
        except Exception:
            return
