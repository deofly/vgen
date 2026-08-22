from __future__ import annotations

import argparse
import json

import pytest

import vgen.cli.join as cli_join
import vgen.cli.main as cli_main
from vgen.cli.client import VgenClientError
from vgen.cli.identity_store import DeviceIdentityStore
from vgen.cli.profile import GatewayProfile, ProfileStore
from vgen.cli.session_store import StoredSession
from vgen.cli.user_enrollment import identity_registration_claim
from vgen.cli.workspace_authorities import PinnedInvite, WorkspaceAuthorityPin
from vgen.crypto import b64url_encode, identity_init
from vgen.protocol.user_enrollment import (
    user_verification_code,
    verify_user_registration_claim,
    verify_workspace_recipient_admission,
)


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):  # type: ignore[no-untyped-def]
        return self.values.get((service, username))

    def set_password(self, service, username, password):  # type: ignore[no-untyped-def]
        self.values[(service, username)] = password

    def delete_password(self, service, username):  # type: ignore[no-untyped-def]
        self.values.pop((service, username), None)


def _invite() -> PinnedInvite:
    issuer = identity_init().keys
    return PinnedInvite(
        invite_id="inv_join",
        secret="one-time-secret-that-must-not-print",
        authority=WorkspaceAuthorityPin(
            workspace_id="wsp_shared",
            user_id="usr_owner",
            root_signing_public_key=b64url_encode(issuer.signing_public_bytes()),
            root_key_id=issuer.root_key_id,
            source="signed_invite_fragment",
        ),
    )


def _args(**updates):  # type: ignore[no-untyped-def]
    values = {
        "profile": "shared",
        "endpoint": "https://gateway.example",
        "identity": "shared",
        "invite_stdin": True,
        "display_name": "Bob",
        "device_name": "Bob Mac",
        "recovery_file": None,
        "pool": None,
        "resume": False,
        "non_interactive": True,
        "json": True,
        "workflow_package": None,
    }
    values.update(updates)
    return argparse.Namespace(**values)


def test_parser_keeps_invite_secret_out_of_argv_and_supports_hidden_prompt() -> None:
    parsed = cli_main.build_parser().parse_args(
        ["join", "--gateway", "https://gateway.example", "--display-name", "Bob"]
    )
    assert parsed.invite_stdin is False
    assert parsed.endpoint == "https://gateway.example"
    assert not hasattr(parsed, "invite")


def test_interactive_invite_uses_hidden_prompt(monkeypatch) -> None:
    expected = _invite()
    monkeypatch.setattr(cli_join.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli_join.getpass, "getpass", lambda _prompt: "hidden-invite-value")
    monkeypatch.setattr(
        cli_join,
        "parse_pinned_invite_uri",
        lambda value: expected if value == "hidden-invite-value" else None,
    )
    assert cli_join._read_invite(from_stdin=False, non_interactive=False) is expected


def test_new_user_direct_join_stages_profile_until_admin_grants_key(
    tmp_path, monkeypatch, capsys
) -> None:
    profiles = ProfileStore(tmp_path / "profiles.yaml")
    identities = DeviceIdentityStore(MemorySecrets())
    _, identity = identities.initialize("shared")
    pins: list[dict] = []
    owner_pins: list[dict] = []
    workflow_installs: list[bool] = []
    requests: list[dict] = []

    class FakeAnonymous:
        def __init__(self, profile):  # type: ignore[no-untyped-def]
            self.profile = profile

        def health(self):  # type: ignore[no-untyped-def]
            return {"ok": True}

        def request(self, method, path, *, json_body, auth):  # type: ignore[no-untyped-def]
            assert (method, path, auth) == ("POST", "/api/v1/auth/enroll", False)
            requests.append(json_body)
            return {
                "user": {"id": "usr_bob"},
                "device": {"id": identity.device_id},
                "enrollment": {
                    "id": "inv_join",
                    "kind": "user",
                    "state": "active",
                    "workspace_id": "wsp_shared",
                    "issuer_user_id": "usr_owner",
                    "subject_user_id": "usr_bob",
                },
            }

        def close(self):
            pass

    class FakeAuthenticated:
        def request(self, method, path):  # type: ignore[no-untyped-def]
            assert (method, path) == ("GET", "/api/v1/workspaces")
            return [{"id": "wsp_shared", "name": "Shared Studio", "key_version": 1}]

        def close(self):
            pass

    class FakeAuthorityStore:
        def pin(self, **values):  # type: ignore[no-untyped-def]
            pins.append(values)

        def pin_owner(self, **values):  # type: ignore[no-untyped-def]
            owner_pins.append(values)

    monkeypatch.setattr(cli_join, "ProfileStore", lambda: profiles)
    monkeypatch.setattr(cli_join, "DeviceIdentityStore", lambda: identities)
    monkeypatch.setattr(cli_join, "GatewayClient", FakeAnonymous)
    monkeypatch.setattr(cli_join, "WorkspaceAuthorityStore", FakeAuthorityStore)
    monkeypatch.setattr(cli_join, "_read_invite", lambda **_kwargs: _invite())
    monkeypatch.setattr(cli_join, "_prepare_identity", lambda _args, _store: identity)
    monkeypatch.setattr(
        cli_join,
        "login_session",
        lambda _profile, _identity: StoredSession(
            "session-must-not-print", 4_000_000_000, "usr_bob", identity.device_id
        ),
    )
    monkeypatch.setattr(cli_join, "_authenticated_client", lambda *_args: FakeAuthenticated())
    monkeypatch.setattr(
        cli_join,
        "_install_official_workflow",
        lambda _args: workflow_installs.append(True),
    )
    monkeypatch.setattr(
        cli_join,
        "sync_workspace_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("no decryptable Workspace key envelope is available for this user/device")
        ),
    )

    cli_join.join_command(_args())

    profile = profiles.get("shared")
    assert profile.user_id == "usr_bob"
    assert profile.pending_workspace == "wsp_shared"
    assert profile.pending_enrollment == "inv_join"
    assert profile.default_workspace is None
    assert profile.default_pool is None
    assert workflow_installs == [True]
    assert pins[0]["workspace_id"] == "wsp_shared"
    assert owner_pins[0]["workspace_id"] == "wsp_shared"
    assert requests[0]["secret"] == "one-time-secret-that-must-not-print"

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["state"] == "workspace_key_pending"
    assert "key-grant-enrollment inv_join" in result["admin_command"]
    assert "one-time-secret-that-must-not-print" not in output
    assert "session-must-not-print" not in output


def test_resume_after_approval_syncs_key_and_commits_workspace_pool_defaults(
    tmp_path, monkeypatch, capsys
) -> None:
    profiles = ProfileStore(tmp_path / "profiles.yaml")
    profiles.put(
        GatewayProfile(
            "shared",
            "https://gateway.example",
            user_id="usr_bob",
            device_id="device_bob",
            key_ref="shared",
            pending_workspace="wsp_shared",
            pending_enrollment="inv_join",
        )
    )
    identities = DeviceIdentityStore(MemorySecrets())
    _, identity = identities.initialize("shared")

    class FakeAuthenticated:
        def request(self, method, path):  # type: ignore[no-untyped-def]
            if path == "/api/v1/workspaces":
                return [{"id": "wsp_shared", "name": "Shared Studio", "key_version": 3}]
            if path == "/api/v1/workspaces/wsp_shared/pools":
                return [{"id": "pol_gpu", "name": "Shared GPU"}]
            raise AssertionError((method, path))

        def close(self):
            pass

    monkeypatch.setattr(cli_join, "ProfileStore", lambda: profiles)
    monkeypatch.setattr(cli_join, "DeviceIdentityStore", lambda: identities)
    monkeypatch.setattr(cli_join, "_install_official_workflow", lambda _args: None)
    monkeypatch.setattr(cli_join, "_authenticated_client", lambda *_args: FakeAuthenticated())
    monkeypatch.setattr(
        cli_join,
        "sync_workspace_key",
        lambda *_args, **_kwargs: {"key_version": 3, "local_key_saved": True},
    )
    monkeypatch.setattr(
        cli_join,
        "_read_invite",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("resume must not reread invite")),
    )

    cli_join.join_command(_args(resume=True, invite_stdin=False))

    completed = profiles.get("shared")
    assert completed.default_workspace == "wsp_shared"
    assert completed.default_pool == "pol_gpu"
    assert completed.pending_workspace is None
    assert completed.pending_enrollment is None
    result = json.loads(capsys.readouterr().out)
    assert result["ready"] is True
    assert result["workspace_key_version"] == 3


def test_resume_waits_cleanly_while_invite_approval_is_pending(
    tmp_path, monkeypatch, capsys
) -> None:
    profiles = ProfileStore(tmp_path / "profiles.yaml")
    profiles.put(
        GatewayProfile(
            "shared",
            "https://gateway.example",
            user_id="usr_bob",
            device_id="device_bob",
            key_ref="shared",
            pending_workspace="wsp_shared",
            pending_enrollment="inv_join",
        )
    )
    identities = DeviceIdentityStore(MemorySecrets())
    identities.initialize("shared")

    class FakeAuthenticated:
        def request(self, method, path):  # type: ignore[no-untyped-def]
            assert (method, path) == ("GET", "/api/v1/workspaces")
            return []

        def close(self):
            pass

    monkeypatch.setattr(cli_join, "ProfileStore", lambda: profiles)
    monkeypatch.setattr(cli_join, "DeviceIdentityStore", lambda: identities)
    monkeypatch.setattr(cli_join, "_install_official_workflow", lambda _args: None)
    monkeypatch.setattr(cli_join, "_authenticated_client", lambda *_args: FakeAuthenticated())
    monkeypatch.setattr(
        cli_join,
        "sync_workspace_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("pending membership must not request a key envelope")
        ),
    )

    cli_join.join_command(_args(resume=True, invite_stdin=False))

    result = json.loads(capsys.readouterr().out)
    assert result["ready"] is False
    assert result["state"] == "approval_pending"
    staged = profiles.get("shared")
    assert staged.default_workspace is None
    assert staged.pending_workspace == "wsp_shared"


def test_existing_user_direct_workspace_member_join_finishes_full_setup(
    tmp_path, monkeypatch, capsys
) -> None:
    profiles = ProfileStore(tmp_path / "profiles.yaml")
    identity_store = DeviceIdentityStore(MemorySecrets())
    _, identity = identity_store.initialize("home")
    profiles.put(
        GatewayProfile(
            "home",
            "https://gateway.example",
            user_id="usr_existing",
            device_id=identity.device_id,
            default_workspace="wsp_previous",
            default_pool="pol_previous",
            key_ref="home",
        )
    )
    claimed: list[dict] = []
    installed: list[bool] = []
    pinned: list[tuple[str, str]] = []

    class FakeClient:
        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]
            if path == "/api/v1/enrollments/claim":
                assert (method, kwargs["auth"]) == ("POST", True)
                claimed.append(kwargs["json_body"])
                return {
                    "id": "inv_join",
                    "kind": "workspace_member",
                    "state": "active",
                    "workspace_id": "wsp_shared",
                    "issuer_user_id": "usr_owner",
                    "subject_user_id": "usr_existing",
                    "subject_id": identity.device_id,
                    "claim": kwargs["json_body"]["claim"],
                    "proof_signature": kwargs["json_body"]["proof_signature"],
                }
            if path == "/api/v1/workspaces":
                return [{"id": "wsp_shared", "name": "Shared Studio", "key_version": 2}]
            if path == "/api/v1/workspaces/wsp_shared/pools":
                return [{"id": "pol_shared", "name": "Shared GPU"}]
            raise AssertionError((method, path, kwargs))

        def close(self):
            pass

    monkeypatch.setattr(cli_join, "ProfileStore", lambda: profiles)
    monkeypatch.setattr(cli_join, "DeviceIdentityStore", lambda: identity_store)
    monkeypatch.setattr(cli_join, "_read_invite", lambda **_kwargs: _invite())
    monkeypatch.setattr(cli_join, "_authenticated_client", lambda *_args: FakeClient())
    monkeypatch.setattr(
        cli_join,
        "_pin_invite_authority",
        lambda _invite_value, workspace_id, issuer_id: pinned.append(
            (workspace_id, issuer_id)
        ),
    )
    monkeypatch.setattr(
        cli_join, "_install_official_workflow", lambda _args: installed.append(True)
    )
    monkeypatch.setattr(
        cli_join,
        "sync_workspace_key",
        lambda *_args, **_kwargs: {"key_version": 2, "local_key_saved": True},
    )

    cli_join.join_command(
        _args(profile=None, endpoint=None, identity=None, non_interactive=True)
    )

    assert len(claimed) == 1
    submitted = claimed[0]
    assert submitted["invite_id"] == "inv_join"
    assert submitted["secret"] == "one-time-secret-that-must-not-print"
    assert submitted["claim"]["device_id"] == identity.device_id
    assert submitted["claim"]["root_key_id"] == identity.root_key_id
    assert verify_user_registration_claim(
        submitted["claim"], submitted["proof_signature"]
    )
    completed = profiles.get("home")
    assert completed.default_workspace == "wsp_shared"
    assert completed.default_pool == "pol_shared"
    assert completed.pending_workspace is None
    assert completed.pending_enrollment is None
    assert installed == [True]
    assert pinned == [("wsp_shared", "usr_owner")]
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["state"] == "active"
    assert result["workspace_key_version"] == 2
    assert result["verification_code"] == user_verification_code(submitted["claim"])
    assert "one-time-secret-that-must-not-print" not in output


def test_existing_user_pending_join_preserves_old_default_then_resume_switches_workspace(
    tmp_path, monkeypatch, capsys
) -> None:
    profiles = ProfileStore(tmp_path / "profiles.yaml")
    identity_store = DeviceIdentityStore(MemorySecrets())
    _, identity = identity_store.initialize("home")
    profiles.put(
        GatewayProfile(
            "home",
            "https://gateway.example",
            user_id="usr_existing",
            device_id=identity.device_id,
            default_workspace="wsp_previous",
            default_pool="pol_previous",
            key_ref="home",
        )
    )
    approved = False
    invite_reads = 0
    installs: list[bool] = []

    class FakeClient:
        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]
            if path == "/api/v1/enrollments/claim":
                assert not approved
                return {
                    "id": "inv_join",
                    "kind": "workspace_member",
                    "state": "pending",
                    "workspace_id": "wsp_shared",
                    "issuer_user_id": "usr_owner",
                    "subject_user_id": "usr_existing",
                    "subject_id": identity.device_id,
                }
            if path == "/api/v1/workspaces":
                assert approved
                return [{"id": "wsp_shared", "name": "Shared Studio", "key_version": 4}]
            if path == "/api/v1/workspaces/wsp_shared/pools":
                return [
                    {"id": "pol_other", "name": "Other GPU"},
                    {"id": "pol_shared", "name": "New GPU"},
                ]
            raise AssertionError((method, path, kwargs))

        def close(self):
            pass

    def read_invite(**_kwargs):  # type: ignore[no-untyped-def]
        nonlocal invite_reads
        invite_reads += 1
        return _invite()

    monkeypatch.setattr(cli_join, "ProfileStore", lambda: profiles)
    monkeypatch.setattr(cli_join, "DeviceIdentityStore", lambda: identity_store)
    monkeypatch.setattr(cli_join, "_read_invite", read_invite)
    monkeypatch.setattr(cli_join, "_authenticated_client", lambda *_args: FakeClient())
    monkeypatch.setattr(cli_join, "_pin_invite_authority", lambda *_args: None)
    monkeypatch.setattr(
        cli_join, "_install_official_workflow", lambda _args: installs.append(True)
    )
    monkeypatch.setattr(
        cli_join,
        "sync_workspace_key",
        lambda *_args, **_kwargs: {"key_version": 4, "local_key_saved": True},
    )

    cli_join.join_command(_args(profile=None, endpoint=None, identity=None))
    pending_result = json.loads(capsys.readouterr().out)
    assert pending_result["state"] == "approval_pending"
    pending = profiles.get("home")
    assert pending.default_workspace == "wsp_previous"
    assert pending.default_pool == "pol_previous"
    assert pending.pending_workspace == "wsp_shared"
    assert pending.pending_enrollment == "inv_join"

    approved = True
    cli_join.join_command(
        _args(
            profile="home",
            endpoint=None,
            identity=None,
            invite_stdin=False,
            resume=True,
            pool="New GPU",
        )
    )
    resumed_result = json.loads(capsys.readouterr().out)
    assert resumed_result["state"] == "active"
    completed = profiles.get("home")
    assert completed.default_workspace == "wsp_shared"
    assert completed.default_pool == "pol_shared"
    assert completed.pending_workspace is None
    assert completed.pending_enrollment is None
    assert invite_reads == 1
    assert installs == [True, True]


def test_existing_user_refuses_non_workspace_member_claim_response(
    tmp_path, monkeypatch
) -> None:
    profiles = ProfileStore(tmp_path / "profiles.yaml")
    identity_store = DeviceIdentityStore(MemorySecrets())
    _, identity = identity_store.initialize("home")
    original = GatewayProfile(
        "home",
        "https://gateway.example",
        user_id="usr_existing",
        device_id=identity.device_id,
        default_workspace="wsp_previous",
        default_pool="pol_previous",
        key_ref="home",
    )
    profiles.put(original)

    class FakeClient:
        def request(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            return {
                "id": "inv_join",
                "kind": "user",
                "state": "active",
                "workspace_id": "wsp_shared",
                "issuer_user_id": "usr_owner",
                "subject_user_id": "usr_existing",
                "subject_id": identity.device_id,
            }

        def close(self):
            pass

    monkeypatch.setattr(cli_join, "ProfileStore", lambda: profiles)
    monkeypatch.setattr(cli_join, "DeviceIdentityStore", lambda: identity_store)
    monkeypatch.setattr(cli_join, "_read_invite", lambda **_kwargs: _invite())
    monkeypatch.setattr(cli_join, "_authenticated_client", lambda *_args: FakeClient())
    monkeypatch.setattr(
        cli_join,
        "_install_official_workflow",
        lambda _args: (_ for _ in ()).throw(AssertionError("must fail before workflow install")),
    )

    with pytest.raises(ValueError, match="workspace_member"):
        cli_join.join_command(_args(profile=None, endpoint=None, identity=None))
    assert profiles.get("home") == original


def test_existing_user_gets_explicit_guidance_when_user_invite_is_rejected(
    tmp_path, monkeypatch
) -> None:
    profiles = ProfileStore(tmp_path / "profiles.yaml")
    identity_store = DeviceIdentityStore(MemorySecrets())
    _, identity = identity_store.initialize("home")
    original = GatewayProfile(
        "home",
        "https://gateway.example",
        user_id="usr_existing",
        device_id=identity.device_id,
        default_workspace="wsp_previous",
        key_ref="home",
    )
    profiles.put(original)

    class FakeClient:
        def request(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            raise VgenClientError(
                240001,
                "INVITE_INVALID_OR_EXPIRED",
                "The invite is invalid, expired, or already used.",
                status_code=410,
            )

        def close(self):
            pass

    monkeypatch.setattr(cli_join, "ProfileStore", lambda: profiles)
    monkeypatch.setattr(cli_join, "DeviceIdentityStore", lambda: identity_store)
    monkeypatch.setattr(cli_join, "_read_invite", lambda **_kwargs: _invite())
    monkeypatch.setattr(cli_join, "_authenticated_client", lambda *_args: FakeClient())

    with pytest.raises(ValueError, match="workspace_member") as raised:
        cli_join.join_command(_args(profile=None, endpoint=None, identity=None))
    assert "user Invite" in str(raised.value)
    assert "one-time-secret-that-must-not-print" not in str(raised.value)
    assert profiles.get("home") == original


def test_admin_key_grant_enrollment_resolves_user_and_current_key_without_copying_ids(
    monkeypatch, capsys
) -> None:
    profile = GatewayProfile(
        "home",
        "https://gateway.example",
        user_id="usr_owner",
        device_id="device_owner",
        default_workspace="wsp_shared",
    )
    identity_store = DeviceIdentityStore(MemorySecrets())
    _, identity = identity_store.initialize("home")
    subject_store = DeviceIdentityStore(MemorySecrets())
    _, subject_identity = subject_store.initialize("bob")
    claim, proof_signature = identity_registration_claim(
        subject_identity,
        invite_id="inv_join",
        display_name="Bob",
        device_name="Bob Mac",
    )
    verification_code = user_verification_code(claim)
    admissions: list[dict] = []
    grants: list[dict] = []

    class FakeClient:
        def __init__(self):
            self.profile = profile

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]
            if path.endswith("/enrollments"):
                return [
                    {
                        "id": "inv_join",
                        "kind": "user",
                        "method": "direct_invite",
                        "state": "active",
                        "workspace_id": "wsp_shared",
                        "issuer_user_id": "usr_owner",
                        "subject_user_id": "usr_bob",
                        "subject_id": subject_identity.device_id,
                        "claim": claim,
                        "proof_signature": proof_signature,
                    }
                ]
            if method == "POST" and path.endswith("/recipient-admissions"):
                admissions.append(kwargs["json_body"])
                return {"stored": True}
            if path == "/api/v1/workspaces":
                return [
                    {
                        "id": "wsp_shared",
                        "owner_user_id": "usr_owner",
                        "key_version": 4,
                    }
                ]
            raise AssertionError((method, path))

        def close(self):
            pass

    monkeypatch.setattr(cli_main, "_client", lambda _profile: FakeClient())
    monkeypatch.setattr(cli_main, "_profile_and_identity", lambda _name: (profile, identity))
    monkeypatch.setattr(
        cli_main,
        "require_local_workspace_owner",
        lambda *_args, **_kwargs: "usr_owner",
    )
    monkeypatch.setattr(
        cli_main,
        "WorkspaceKeyStore",
        lambda: type("Keys", (), {"load": lambda self, _workspace, _version: b"k" * 32})(),
    )
    monkeypatch.setattr(
        cli_main,
        "grant_workspace_key",
        lambda *_args, **kwargs: grants.append(kwargs)
        or {"id": f"wke_{kwargs['recipient_type']}"},
    )

    cli_main._workspace_command(
        argparse.Namespace(
            workspace_action="key-grant-enrollment",
            enrollment_id="inv_join",
            verification_code=verification_code,
            workspace=None,
            profile="home",
        )
    )

    result = json.loads(capsys.readouterr().out)
    assert len(admissions) == 1
    assert admissions[0]["enrollment_id"] == "inv_join"
    assert verify_workspace_recipient_admission(
        admissions[0]["signed_admission"],
        identity.root_signing_public_key,
        workspace_id="wsp_shared",
        owner_user_id="usr_owner",
        subject_user_id="usr_bob",
        enrollment_id="inv_join",
    )
    assert [grant["recipient_type"] for grant in grants] == ["user_recovery", "device"]
    assert grants[0]["recipient_id"] == "usr_bob"
    assert grants[1]["recipient_id"] == subject_identity.device_id
    assert result["workspace_key_grant"] == {
        "device_envelope_id": "wke_device",
        "envelope_id": "wke_user_recovery",
        "granted": True,
        "key_version": 4,
        "recipient_id": "usr_bob",
        "recipient_type": "user_recovery",
    }


def test_direct_invite_waits_for_claim_and_grants_key_automatically(
    monkeypatch, capsys
) -> None:
    profile = GatewayProfile(
        "home",
        "https://gateway.example",
        user_id="usr_owner",
        device_id="device_owner",
        default_workspace="wsp_shared",
    )
    identity_store = DeviceIdentityStore(MemorySecrets())
    _, identity = identity_store.initialize("home")
    subject_store = DeviceIdentityStore(MemorySecrets())
    _, subject_identity = subject_store.initialize("bob")
    claim, proof_signature = identity_registration_claim(
        subject_identity,
        invite_id="inv_wait",
        display_name="Bob",
        device_name="Bob Mac",
    )
    verification_code = user_verification_code(claim)
    admissions: list[dict] = []
    grants: list[dict] = []

    class FakeClient:
        def __init__(self):
            self.profile = profile

        def request(self, method, path, **kwargs):  # type: ignore[no-untyped-def]
            if method == "POST" and path.endswith("/invites"):
                assert kwargs["json_body"]["method"] == "direct_invite"
                return {
                    "invite_uri": "vgen://join/inv_wait#secret-value-with-enough-entropy",
                    "enrollment": {
                        "id": "inv_wait",
                        "workspace_id": "wsp_shared",
                        "issuer_user_id": "usr_owner",
                    },
                }
            if path.endswith("/enrollments"):
                return [
                    {
                        "id": "inv_wait",
                        "kind": "user",
                        "method": "direct_invite",
                        "state": "active",
                        "workspace_id": "wsp_shared",
                        "issuer_user_id": "usr_owner",
                        "subject_user_id": "usr_bob",
                        "subject_id": subject_identity.device_id,
                        "claim": claim,
                        "proof_signature": proof_signature,
                    }
                ]
            if method == "POST" and path.endswith("/recipient-admissions"):
                admissions.append(kwargs["json_body"])
                return {"stored": True}
            if path == "/api/v1/workspaces":
                return [
                    {
                        "id": "wsp_shared",
                        "owner_user_id": "usr_owner",
                        "key_version": 2,
                    }
                ]
            raise AssertionError((method, path))

        def close(self):
            pass

    monkeypatch.setattr(cli_main, "_client", lambda _profile: FakeClient())
    monkeypatch.setattr(cli_main, "_profile_and_identity", lambda _name: (profile, identity))
    monkeypatch.setattr(
        cli_main,
        "require_local_workspace_owner",
        lambda *_args, **_kwargs: "usr_owner",
    )
    monkeypatch.setattr(
        cli_main,
        "WorkspaceKeyStore",
        lambda: type("Keys", (), {"load": lambda self, _workspace, _version: b"k" * 32})(),
    )
    monkeypatch.setattr(
        cli_main,
        "grant_workspace_key",
        lambda *_args, **kwargs: grants.append(kwargs)
        or {"id": f"wke_{kwargs['recipient_type']}"},
    )

    cli_main._workspace_command(
        argparse.Namespace(
            workspace_action="invite",
            workspace=None,
            kind="user",
            method="direct_invite",
            relationship="member",
            scope=[],
            subject_key_fingerprint=None,
            ttl=1800,
            wait=True,
            timeout=10,
            wait_interval=0.01,
            verification_code=verification_code,
            profile="home",
        )
    )

    output = capsys.readouterr()
    assert output.out.startswith("vgen://join/inv_wait#")
    assert "Workspace 加密密钥已自动发放" in output.err
    assert len(admissions) == 1
    assert admissions[0]["enrollment_id"] == "inv_wait"
    assert verify_workspace_recipient_admission(
        admissions[0]["signed_admission"],
        identity.root_signing_public_key,
        workspace_id="wsp_shared",
        owner_user_id="usr_owner",
        subject_user_id="usr_bob",
        enrollment_id="inv_wait",
    )
    assert [grant["recipient_type"] for grant in grants] == ["user_recovery", "device"]
    assert grants[0]["recipient_id"] == "usr_bob"
    assert grants[1]["recipient_id"] == subject_identity.device_id
    assert all(grant["key_version"] == 2 for grant in grants)
