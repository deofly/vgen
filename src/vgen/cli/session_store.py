from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Protocol

import keyring


class SecretBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


@dataclass(frozen=True, slots=True)
class StoredSession:
    token: str
    expires_at: float
    user_id: str | None = None
    device_id: str | None = None

    @property
    def expired(self) -> bool:
        return self.expires_at <= time.time() + 5


class SessionStore:
    """Short-lived Gateway sessions stored in the OS keychain.

    Session tokens never enter the YAML profile or command arguments. An
    expired token is deleted eagerly and re-created with a signed challenge.
    """

    SERVICE = "vgen.session.v1"

    def __init__(self, backend: SecretBackend | None = None) -> None:
        self.backend = backend or keyring

    def load(self, profile_name: str) -> StoredSession | None:
        encoded = self.backend.get_password(self.SERVICE, profile_name)
        if not encoded:
            return None
        try:
            raw = json.loads(encoded)
            session = StoredSession(
                token=str(raw["token"]),
                expires_at=float(raw["expires_at"]),
                user_id=raw.get("user_id"),
                device_id=raw.get("device_id"),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.delete(profile_name)
            return None
        if session.expired:
            self.delete(profile_name)
            return None
        return session

    def save(self, profile_name: str, session: StoredSession) -> None:
        self.backend.set_password(
            self.SERVICE,
            profile_name,
            json.dumps(
                {
                    "token": session.token,
                    "expires_at": session.expires_at,
                    "user_id": session.user_id,
                    "device_id": session.device_id,
                },
                separators=(",", ":"),
            ),
        )

    def delete(self, profile_name: str) -> None:
        try:
            self.backend.delete_password(self.SERVICE, profile_name)
        except Exception:
            # Keyring backends differ on how a missing entry is reported.
            return
