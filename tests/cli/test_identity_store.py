from __future__ import annotations

import pytest

from vgen.cli.identity_store import DeviceIdentityStore, IdentityStoreError
from vgen.crypto import verify_device_certificate


class MemorySecrets:
    def __init__(self) -> None:
        self.values = {}

    def get_password(self, service, username):
        return self.values.get((service, username))

    def set_password(self, service, username, password):
        self.values[(service, username)] = password

    def delete_password(self, service, username):
        del self.values[(service, username)]


def test_identity_init_and_mnemonic_recovery_create_certified_devices() -> None:
    secrets = MemorySecrets()
    store = DeviceIdentityStore(secrets)
    bundle, first = store.initialize("first")
    second = store.recover_mnemonic(bundle.mnemonic, "second")
    assert len(bundle.recovery_words) == 24
    assert first.root_key_id == second.root_key_id
    assert first.device_id != second.device_id
    assert verify_device_certificate(
        first.certificate,
        bundle.keys.signing_public_bytes(),
    )
    restored = store.load("second")
    assert restored.device_id == second.device_id
    assert restored.root_keys.encryption_private_bytes() == bundle.keys.encryption_private_bytes()
    assert restored.root_keys.signing_private_bytes() == bundle.keys.signing_private_bytes()


def test_identity_store_refuses_to_replace_an_alias_without_explicit_overwrite() -> None:
    secrets = MemorySecrets()
    store = DeviceIdentityStore(secrets)
    assert not store.exists("primary")
    bundle, first = store.initialize("primary")
    assert store.exists("primary")

    with pytest.raises(IdentityStoreError, match="already exists"):
        store.initialize("primary")
    with pytest.raises(IdentityStoreError, match="already exists"):
        store.recover_mnemonic(bundle.mnemonic, "primary")

    recovered = store.recover_mnemonic(bundle.mnemonic, "primary", overwrite=True)
    assert recovered.root_key_id == first.root_key_id
    assert recovered.device_id != first.device_id
