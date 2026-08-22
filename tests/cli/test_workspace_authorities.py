from __future__ import annotations

from types import SimpleNamespace

import pytest

from vgen.cli.main import (
    LEGACY_OWNER_MIGRATION_CONFIRMATION,
    _confirm_legacy_owner_migration,
    build_parser,
)
from vgen.cli.workspace_authorities import (
    WorkspaceAuthorityError,
    WorkspaceAuthorityStore,
    decorate_invite_uri,
    parse_pinned_invite_uri,
)
from vgen.crypto import b64url_encode, identity_init


class MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))


def test_signed_invite_fragment_binds_secret_workspace_and_issuer_root() -> None:
    issuer = identity_init().keys
    uri = decorate_invite_uri(
        "vgen://join/inv_example#secret-value-with-entropy",
        workspace_id="wsp_example",
        issuer_user_id="usr_owner",
        identity=issuer,
    )

    parsed = parse_pinned_invite_uri(uri)

    assert parsed.invite_id == "inv_example"
    assert parsed.secret == "secret-value-with-entropy"
    assert parsed.authority.workspace_id == "wsp_example"
    assert parsed.authority.user_id == "usr_owner"
    assert parsed.authority.root_signing_public_key == b64url_encode(issuer.signing_public_bytes())
    assert "secret=" in uri.split("#", 1)[1]
    with pytest.raises(WorkspaceAuthorityError, match="valid out-of-band"):
        parse_pinned_invite_uri(uri.replace("secret-value", "attacker-value"))


def test_authority_pin_is_write_once_and_gateway_substitution_fails_closed() -> None:
    trusted = identity_init().keys
    attacker = identity_init().keys
    store = WorkspaceAuthorityStore(backend=MemoryKeyring())
    pin = store.pin(
        workspace_id="wsp_example",
        user_id="usr_admin",
        root_signing_public_key=b64url_encode(trusted.signing_public_bytes()),
        root_key_id=trusted.root_key_id,
        source="explicit_out_of_band",
    )

    assert (
        store.require(
            workspace_id="wsp_example",
            user_id="usr_admin",
            presented_root_signing_public_key=pin.root_signing_public_key,
            presented_root_key_id=pin.root_key_id,
        )
        == pin
    )
    with pytest.raises(WorkspaceAuthorityError, match="substituted"):
        store.require(
            workspace_id="wsp_example",
            user_id="usr_admin",
            presented_root_signing_public_key=b64url_encode(attacker.signing_public_bytes()),
        )
    with pytest.raises(WorkspaceAuthorityError, match="different root"):
        store.pin(
            workspace_id="wsp_example",
            user_id="usr_admin",
            root_signing_public_key=b64url_encode(attacker.signing_public_bytes()),
            source="gateway_response",
        )
    assert store.load("wsp_example", "usr_admin") == pin


def test_unpinned_authority_is_never_silently_learned() -> None:
    authority = identity_init().keys
    store = WorkspaceAuthorityStore(backend=MemoryKeyring())

    with pytest.raises(WorkspaceAuthorityError, match="not pinned locally"):
        store.require(
            workspace_id="wsp_example",
            user_id="usr_admin",
            presented_root_signing_public_key=b64url_encode(authority.signing_public_bytes()),
        )
    assert store.load("wsp_example", "usr_admin") is None


def test_workspace_owner_pin_is_unique_and_admin_self_pin_cannot_replace_it() -> None:
    owner = identity_init().keys
    admin = identity_init().keys
    store = WorkspaceAuthorityStore(backend=MemoryKeyring())
    pin = store.pin_owner(
        workspace_id="wsp_example",
        user_id="usr_owner",
        root_signing_public_key=b64url_encode(owner.signing_public_bytes()),
        root_key_id=owner.root_key_id,
        source="signed_invite_fragment",
    )
    # A normal per-user authority pin does not grant the unique Owner role.
    store.pin(
        workspace_id="wsp_example",
        user_id="usr_admin",
        root_signing_public_key=b64url_encode(admin.signing_public_bytes()),
        root_key_id=admin.root_key_id,
        source="local_user_root",
    )
    with pytest.raises(WorkspaceAuthorityError, match="not the pinned Workspace Owner"):
        store.require_owner_identity(
            workspace_id="wsp_example",
            user_id="usr_admin",
            root_signing_public_key=b64url_encode(admin.signing_public_bytes()),
            root_key_id=admin.root_key_id,
        )
    with pytest.raises(WorkspaceAuthorityError, match="different User or root key"):
        store.pin_owner(
            workspace_id="wsp_example",
            user_id="usr_admin",
            root_signing_public_key=b64url_encode(admin.signing_public_bytes()),
            root_key_id=admin.root_key_id,
            source="gateway_response",
        )
    assert store.load_owner("wsp_example") == pin


def test_workspace_help_exposes_explicit_legacy_owner_migration(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as help_exit:
        parser.parse_args(["workspace", "owner-migrate", "--help"])
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    assert "--accept-legacy-tofu" in help_text
    parsed = parser.parse_args(
        ["workspace", "owner-migrate", "--accept-legacy-tofu"]
    )
    assert parsed.workspace_action == "owner-migrate"
    assert parsed.accept_legacy_tofu is True


def test_legacy_owner_migration_needs_prompt_or_explicit_dangerous_flag(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(ValueError, match="--accept-legacy-tofu"):
        _confirm_legacy_owner_migration(
            endpoint="https://gateway.example",
            workspace_id="wsp_example",
            user_id="usr_owner",
            root_key_id="root_example",
            accept_legacy_tofu=False,
        )
    warning = capsys.readouterr().err
    assert "https://gateway.example" in warning
    assert "wsp_example" in warning
    assert "usr_owner" in warning
    assert "root_example" in warning

    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", lambda _prompt: LEGACY_OWNER_MIGRATION_CONFIRMATION)
    _confirm_legacy_owner_migration(
        endpoint="https://gateway.example",
        workspace_id="wsp_example",
        user_id="usr_owner",
        root_key_id="root_example",
        accept_legacy_tofu=False,
    )
