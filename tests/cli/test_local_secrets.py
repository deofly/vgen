from __future__ import annotations

import time

from vgen.cli.session_store import SessionStore, StoredSession
from vgen.cli.workspace_keys import WorkspaceKeyStore


class MemorySecrets:
    def __init__(self) -> None:
        self.values = {}

    def get_password(self, service, username):
        return self.values.get((service, username))

    def set_password(self, service, username, password):
        self.values[(service, username)] = password

    def delete_password(self, service, username):
        self.values.pop((service, username), None)


def test_short_session_expires_and_is_removed() -> None:
    backend = MemorySecrets()
    store = SessionStore(backend)
    store.save("local", StoredSession("token", time.time() - 1, "usr_1", "dev_1"))
    assert store.load("local") is None
    assert backend.values == {}


def test_workspace_data_key_stays_in_secret_backend() -> None:
    backend = MemorySecrets()
    store = WorkspaceKeyStore(backend)
    key = store.create("wsp_1", 2)
    assert len(key) == 32
    assert store.load("wsp_1", 2) == key
    assert all("wsp_1" not in value for value in backend.values.values())
