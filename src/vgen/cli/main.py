from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import shlex
import sys
import time
import uuid
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
from packaging.version import InvalidVersion, Version

from vgen import __version__
from vgen.artifacts import (
    ArtifactTransferError,
    HttpArtifactAdapter,
    OssStsArtifactAdapter,
    TransferTicket,
    with_safe_media_extension,
)
from vgen.crypto import (
    HPKE_ALGORITHM,
    DeviceKeys,
    PayloadCiphertext,
    b64url_decode,
    b64url_encode,
    build_allocation_proof_payload,
    build_maintenance_intent_payload,
    canonical_json,
    device_key_id,
    encrypt_payload,
    export_recovery_file,
    generate_task_data_key,
    sign_allocation_proof,
    sign_http_request,
    sign_key_manifest,
    sign_maintenance_intent,
    sign_message,
    task_aad,
    unwrap_task_key_for_workspace,
    verify_allocation_proof,
    verify_key_manifest,
    wrap_task_key,
    wrap_task_key_for_workspace,
)
from vgen.market import WorkflowRegistry
from vgen.market.builder import build_comfy_graph, load_json
from vgen.market.models import WorkflowManifest, WorkflowVariant
from vgen.market.registry import (
    RegistryError,
    build_archive,
    sign_package,
    validate_package,
)
from vgen.protocol import ErrorCode, VGenError, get_error_spec, new_id
from vgen.protocol.user_enrollment import user_verification_code

from .artifacts import (
    LocalTaskInput,
    download_and_decrypt_output,
    encrypt_and_upload_inputs,
)
from .auth import (
    authenticate_device_session,
    login_service_session,
    login_session,
)
from .client import GatewayClient, VgenClientError, cli_exit_code
from .device_migration import register_recovered_device
from .identity_store import DeviceIdentity, DeviceIdentityStore, IdentityStoreError
from .join import join_command
from .profile import GatewayProfile, ProfileError, ProfileStore
from .service_credentials import (
    ServiceCredentialError,
    ServiceCredentials,
    ServiceCredentialStore,
    ServiceSessionStore,
    StoredServiceSession,
)
from .session_store import SessionStore, StoredSession
from .setup import prompt_bootstrap_code, setup_command
from .upgrade import stable_worker_wheel, upgrade_command
from .user_enrollment import identity_registration_claim, sign_enrollment_admission
from .workspace_authorities import (
    PinnedInvite,
    WorkspaceAuthorityError,
    WorkspaceAuthorityStore,
    decorate_invite_uri,
    parse_pinned_invite_uri,
)
from .workspace_envelopes import (
    LegacyOwnerMigrationRequired,
    grant_workspace_key,
    initialize_workspace_keys,
    migrate_legacy_workspace_owner,
    require_local_workspace_owner,
    rotate_workspace_key,
    sync_service_workspace_key,
    sync_workspace_key,
)
from .workspace_keys import WorkspaceKeyError, WorkspaceKeyStore


def _json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _task_list_datetime(value: object) -> str:
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        return "-"
    try:
        return datetime.fromtimestamp(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "-"


def _task_list_cell(value: object, *, width: int | None = None) -> str:
    raw = "" if value is None else str(value)
    normalized = " ".join("".join(char if char.isprintable() else " " for char in raw).split())
    if not normalized:
        normalized = "-"
    if width is not None and len(normalized) > width:
        return normalized[: max(1, width - 1)] + "…"
    return normalized


def _print_task_list(page: Mapping[str, Any]) -> None:
    items = page.get("items")
    rows = items if isinstance(items, list) else []
    if not rows:
        print("没有符合条件的任务。")
        print(f"本页 0 条，共 {int(page.get('total') or 0)} 条")
        return

    sort = str(page.get("sort") or "created")
    time_field = "updated_at" if sort == "updated" else "created_at"
    time_heading = "UPDATED" if sort == "updated" else "CREATED"
    print(
        f"{'TASK ID':<31} {'STATE':<12} {'PRI':>3} {time_heading:<19} "
        f"{'SUBMITTER':<16} {'WORKER':<22} WORKFLOW"
    )
    for item in rows:
        if not isinstance(item, Mapping):
            continue
        submitter = item.get("submitted_by")
        submitter_name = submitter.get("display_name") if isinstance(submitter, Mapping) else None
        worker = item.get("worker")
        worker_name = worker.get("name") if isinstance(worker, Mapping) else None
        state = _task_list_cell(item.get("state"), width=12)
        queue_position = item.get("queue_position")
        if state == "queued" and isinstance(queue_position, int) and queue_position > 0:
            state = _task_list_cell(f"queued #{queue_position}", width=12)
        print(
            f"{_task_list_cell(item.get('id'), width=31):<31} "
            f"{state:<12} "
            f"{int(item.get('priority') or 0):>3} "
            f"{_task_list_datetime(item.get(time_field)):<19} "
            f"{_task_list_cell(submitter_name, width=16):<16} "
            f"{_task_list_cell(worker_name, width=22):<22} "
            f"{_task_list_cell(item.get('workflow_ref'), width=48)}"
        )

    print()
    order = str(page.get("order") or "desc")
    print(
        f"本页 {len(rows)} 条，共 {int(page.get('total') or 0)} 条"
        f"（排序：{sort} {order}）"
    )
    next_command = page.get("next")
    if isinstance(next_command, str) and next_command:
        print(f"下一页：{next_command}")
    print("查看明细：vgen task show <task_id>")


def _normalize_task_list_sort(page: dict[str, Any], *, sort: str, order: str) -> None:
    response_sort = page.get("sort")
    response_order = page.get("order")
    if response_sort is None and response_order is None:
        if sort != "created" or order != "desc":
            raise ValueError(
                "Gateway does not support task list sorting; upgrade the Gateway first"
            )
    elif response_sort != sort or response_order != order:
        raise ValueError("Gateway returned a different task list sort than requested")
    page["sort"] = sort
    page["order"] = order


LEGACY_OWNER_MIGRATION_CONFIRMATION = "MIGRATE-LEGACY-OWNER"


def _upgrade_available(runtime_version: object) -> bool | None:
    if not runtime_version:
        return None
    try:
        return Version(str(runtime_version)) < Version(__version__)
    except InvalidVersion:
        return None


def _device_registration(identity: DeviceIdentity, *, name: str) -> dict[str, Any]:
    certificate = identity.certificate.to_dict()
    return {
        "root_key_id": identity.root_key_id,
        "device_id": identity.device_id,
        "device_name": name,
        "device_signing_public_key": certificate["payload"]["signing_public_key"],
        "device_encryption_public_key": certificate["payload"]["encryption_public_key"],
        "device_certificate": certificate,
        "root_signing_public_key": identity.root_signing_public_key,
        "root_encryption_public_key": identity.root_encryption_public_key,
    }


def _signer(identity: DeviceIdentity):  # type: ignore[no-untyped-def]
    def sign(method: str, path: str, body: bytes) -> dict[str, str]:
        return sign_http_request(
            identity.device_keys,
            method=method,
            path=path,
            body=body,
        ).to_headers()

    return sign


def _profile_and_identity(profile_name: str | None = None) -> tuple[GatewayProfile, DeviceIdentity]:
    profile = ProfileStore().get(profile_name)
    if profile.principal_type != "device":
        raise ValueError("this command requires a User Device profile")
    identity = DeviceIdentityStore().load(profile.key_ref or "default")
    return profile, identity


def _service_credentials_for_profile(profile: GatewayProfile) -> ServiceCredentials:
    if profile.principal_type != "service" or not profile.service_id:
        raise ValueError("profile is not bound to an API Service")
    credentials = ServiceCredentialStore().load(
        profile.service_key_ref or profile.service_id,
        file_path=(
            Path(profile.service_credentials_file) if profile.service_credentials_file else None
        ),
    )
    if credentials.service_id != profile.service_id:
        raise ServiceCredentialError(
            "Service credentials do not match the Service bound to this profile."
        )
    return credentials


def _service_signer(credentials: ServiceCredentials):  # type: ignore[no-untyped-def]
    def sign(method: str, path: str, body: bytes) -> dict[str, str]:
        return sign_http_request(
            credentials.device_keys,
            method=method,
            path=path,
            body=body,
        ).to_headers()

    return sign


def _login_and_store_service_session(
    profile: GatewayProfile, credentials: ServiceCredentials
) -> StoredServiceSession:
    raw = login_service_session(profile, credentials.service_id, credentials.device_keys)
    session = StoredServiceSession(
        token=str(raw["token"]),
        expires_at=float(raw["expires_at"]),
        service_id=str(raw["service_id"]),
    )
    if session.service_id != credentials.service_id:
        raise ServiceCredentialError("Gateway returned a session for a different Service.")
    ServiceSessionStore().save(profile.name, session)
    return session


def _client(profile_name: str | None = None, *, login: bool = True) -> GatewayClient:
    profile = ProfileStore().get(profile_name)
    if profile.principal_type == "service":
        if not login:
            return GatewayClient(profile)
        credentials = _service_credentials_for_profile(profile)
        session = ServiceSessionStore().load(profile.name, credentials.service_id)
        if session is None:
            session = _login_and_store_service_session(profile, credentials)

        def refresh() -> str:
            return _login_and_store_service_session(profile, credentials).token

        return GatewayClient(
            profile,
            session_token=session.token,
            signer=_service_signer(credentials),
            token_refresher=refresh,
        )
    profile, identity = _profile_and_identity(profile.name)
    session = SessionStore().load(profile.name)
    if session is None and login:
        session = login_session(profile, identity)
    return GatewayClient(
        profile,
        session_token=session.token if session else None,
        signer=_signer(identity) if session else None,
        token_refresher=(lambda: login_session(profile, identity).token) if login else None,
    )


def _read_invite() -> PinnedInvite:
    value = sys.stdin.read().strip()
    return parse_pinned_invite_uri(value)


def _pin_invite_authority(
    invite: PinnedInvite, response_workspace_id: str, response_issuer_user_id: str
) -> None:
    if response_workspace_id != invite.authority.workspace_id:
        raise ValueError("Gateway enrollment Workspace does not match the trusted Invite URI")
    if response_issuer_user_id != invite.authority.user_id:
        raise ValueError("Gateway enrollment issuer does not match the trusted Invite URI")
    WorkspaceAuthorityStore().pin(
        workspace_id=invite.authority.workspace_id,
        user_id=invite.authority.user_id,
        root_signing_public_key=invite.authority.root_signing_public_key,
        root_key_id=invite.authority.root_key_id,
        source=invite.authority.source,
    )


def _identity_command(args: argparse.Namespace) -> None:
    store = DeviceIdentityStore()
    if args.identity_action == "init":
        bundle, identity = store.initialize(args.alias, overwrite=args.overwrite)
        if args.dangerously_export_recovery:
            target = Path(args.dangerously_export_recovery).expanduser()
            if target.exists():
                raise ValueError(f"refusing to overwrite recovery file: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(export_recovery_file(bundle.mnemonic))
        print("Recovery phrase (shown once; keep it offline):", file=sys.stderr)
        print(bundle.mnemonic)
        _json(
            {
                "alias": args.alias,
                "device_id": identity.device_id,
                "root_key_id": identity.root_key_id,
            }
        )
        return
    if args.identity_action == "recover":
        if args.private_key_file:
            identity = store.recover_file(
                Path(args.private_key_file).expanduser().read_bytes(),
                args.alias,
                overwrite=args.overwrite,
            )
        else:
            if sys.stdin.isatty():
                mnemonic = getpass.getpass("24-word recovery phrase: ")
            else:
                mnemonic = sys.stdin.read().strip()
            identity = store.recover_mnemonic(
                mnemonic,
                args.alias,
                overwrite=args.overwrite,
            )
        session = None
        if args.profile:
            profile = ProfileStore().get(args.profile)
            session = register_recovered_device(profile, identity, device_name=args.device_name)
        _json(
            {
                "alias": args.alias,
                "device_id": identity.device_id,
                "root_key_id": identity.root_key_id,
                "profile": args.profile,
                "user_id": session.user_id if session else None,
            }
        )
        return
    if args.identity_action in {"show", "device"}:
        identity = store.load(args.alias)
        signing_public_key = identity.certificate.to_dict()["payload"]["signing_public_key"]
        _json(
            {
                "alias": identity.alias,
                "device_id": identity.device_id,
                "device_key_id": identity.device_keys.key_id,
                "device_key_fingerprint": hashlib.sha256(signing_public_key.encode()).hexdigest(),
                "root_key_id": identity.root_key_id,
                "certificate": identity.certificate.to_dict(),
            }
        )
        return
    if args.identity_action == "revoke":
        profile, identity = _profile_and_identity(args.profile)
        client = _client(profile.name)
        device_id = args.device_id or profile.device_id or identity.device_id
        try:
            _json(
                client.request(
                    "POST",
                    f"/api/v1/devices/{device_id}/revoke",
                    json_body={},
                    idempotency_key=f"device-revoke:{device_id}",
                )
            )
        finally:
            client.close()
        if args.forget_local:
            SessionStore().delete(profile.name)
            if device_id == identity.device_id:
                store.delete(identity.alias)
        return
    if args.identity_action == "login":
        profile, identity = _profile_and_identity(args.profile)
        session = login_session(profile, identity)
        _json(
            {
                "profile": profile.name,
                "user_id": session.user_id,
                "device_id": session.device_id,
                "expires_at": session.expires_at,
            }
        )
        return
    if args.identity_action == "logout":
        profile = ProfileStore().get(args.profile)
        SessionStore().delete(profile.name)
        _json({"profile": profile.name, "logged_out": True})
        return
    if args.identity_action == "enroll":
        invite = _read_invite()
        invite_id, secret = invite.invite_id, invite.secret
        profile, identity = _profile_and_identity(args.profile)
        claim, proof_signature = identity_registration_claim(
            identity,
            invite_id=invite_id,
            display_name=args.display_name,
            device_name=args.device_name,
        )
        client = GatewayClient(profile)
        try:
            response = client.request(
                "POST",
                "/api/v1/auth/enroll",
                json_body={
                    "invite_id": invite_id,
                    "secret": secret,
                    "claim": claim,
                    "proof_signature": proof_signature,
                },
                auth=False,
            )
        finally:
            client.close()
        _pin_invite_authority(
            invite,
            str(response["enrollment"]["workspace_id"]),
            str(response["enrollment"]["issuer_user_id"]),
        )
        WorkspaceAuthorityStore().pin_owner(
            workspace_id=invite.authority.workspace_id,
            user_id=invite.authority.user_id,
            root_signing_public_key=invite.authority.root_signing_public_key,
            root_key_id=invite.authority.root_key_id,
            source=invite.authority.source,
        )
        profile = ProfileStore().update_binding(
            profile.name,
            user_id=response["user"]["id"],
            device_id=response["device"]["id"],
        )
        session = login_session(profile, identity)
        _json(
            {
                "profile": profile.name,
                "user_id": session.user_id,
                "device_id": session.device_id,
                "enrollment": response["enrollment"],
                "verification_code": user_verification_code(claim),
            }
        )
        return
    if args.identity_action == "device-enroll":
        invite = _read_invite()
        invite_id, secret = invite.invite_id, invite.secret
        profile, identity = _profile_and_identity(args.profile)
        proof_signature = b64url_encode(
            sign_message(
                identity.device_keys.signing_private_key,
                canonical_json(
                    {
                        "version": 1,
                        "invite_id": invite_id,
                        "device_id": identity.device_id,
                    }
                ),
                context=b"vgen-device-enrollment-v1",
            )
        )
        client = GatewayClient(profile)
        try:
            response = client.request(
                "POST",
                "/api/v1/devices/enroll",
                json_body={
                    "invite_id": invite_id,
                    "secret": secret,
                    **_device_registration(identity, name=args.device_name),
                    "proof_signature": proof_signature,
                },
                auth=False,
            )
        finally:
            client.close()
        _pin_invite_authority(
            invite,
            str(response["enrollment"]["workspace_id"]),
            str(response["enrollment"]["issuer_user_id"]),
        )
        profile = ProfileStore().update_binding(
            profile.name,
            user_id=response["user_id"],
            device_id=response["device_id"],
        )
        if response["enrollment"]["state"] == "active":
            session = login_session(profile, identity)
            response["session"] = {
                "expires_at": session.expires_at,
                "device_id": session.device_id,
            }
        _json(response)
        return
    raise ValueError("unsupported identity action")


def _profile_command(args: argparse.Namespace) -> None:
    store = ProfileStore()
    if args.profile_action == "add":
        profile = GatewayProfile(
            name=args.name,
            endpoint=args.endpoint,
            default_workspace=args.workspace,
            key_ref=args.identity,
        )
        store.put(profile, make_current=not args.no_use)
        _json(asdict(profile))
    elif args.profile_action == "use":
        store.use(args.name)
        _json({"current": args.name})
    elif args.profile_action == "show":
        _json(asdict(store.get(args.name)))
    elif args.profile_action == "list":
        current, profiles = store.load()
        _json({"current": current, "profiles": [asdict(item) for item in profiles.values()]})
    elif args.profile_action == "endpoint-set":
        current = store.get(args.profile)
        values = asdict(current)
        values["endpoint"] = args.endpoint
        candidate = GatewayProfile(**values)

        anonymous = GatewayClient(candidate)
        try:
            health = anonymous.health()
        finally:
            anonymous.close()
        if health.get("ok") is not True:
            raise ValueError("the new Gateway health check did not return ok=true")

        if current.principal_type == "service":
            credentials = _service_credentials_for_profile(current)
            raw_session = login_service_session(
                candidate, credentials.service_id, credentials.device_keys
            )
            if str(raw_session.get("service_id")) != credentials.service_id:
                raise ValueError("the new Gateway authenticated a different API Service")
            ServiceSessionStore().delete(current.name, credentials.service_id)
        else:
            identity = DeviceIdentityStore().load(current.key_ref or "default")
            session = authenticate_device_session(candidate, identity)
            if current.user_id and session.user_id != current.user_id:
                raise ValueError("the new Gateway authenticated a different User")
            expected_device_id = current.device_id or identity.device_id
            if session.device_id != expected_device_id:
                raise ValueError("the new Gateway authenticated a different Device")
            SessionStore().delete(current.name)

        updated = store.update_binding(current.name, endpoint=candidate.endpoint)
        _json(
            {
                "profile": updated.name,
                "endpoint": updated.endpoint,
                "verified": True,
                "next": (
                    "vgen broker service-refresh --profile " + updated.name
                    if updated.home_broker_id
                    else None
                ),
            }
        )


def _gateway_command(args: argparse.Namespace) -> None:
    if args.gateway_action == "health":
        client = _client(args.profile)
        try:
            _json(client.status())
        finally:
            client.close()
        return
    if args.gateway_action != "bootstrap":
        raise ValueError("unsupported gateway action")
    profile, identity = _profile_and_identity(args.profile)
    code = sys.stdin.read().strip() if not sys.stdin.isatty() else prompt_bootstrap_code()
    client = GatewayClient(profile)
    try:
        response = client.request(
            "POST",
            "/api/v1/auth/bootstrap",
            json_body={
                "bootstrap_code": code,
                "display_name": args.display_name,
                **_device_registration(identity, name=args.device_name),
            },
            auth=False,
        )
    finally:
        client.close()
    session_data = response.get("session") or response
    session = StoredSession(
        token=str(session_data.get("token") or response.get("session_token")),
        expires_at=float(session_data.get("expires_at") or response["expires_at"]),
        user_id=response.get("user_id") or response.get("user", {}).get("id"),
        device_id=response.get("device_id") or response.get("device", {}).get("id"),
    )
    SessionStore().save(profile.name, session)
    ProfileStore().update_binding(
        profile.name, user_id=session.user_id, device_id=session.device_id
    )
    _json({"profile": profile.name, "user_id": session.user_id, "device_id": session.device_id})


def _service_command(args: argparse.Namespace) -> None:
    profile_store = ProfileStore()
    profile = profile_store.get(args.profile)
    credential_store = ServiceCredentialStore()
    if args.service_action == "enroll":
        invite = _read_invite()
        invite_id, secret = invite.invite_id, invite.secret
        keys = DeviceKeys.generate()
        signing_public_key = b64url_encode(keys.signing_public_bytes())
        encryption_public_key = b64url_encode(keys.encryption_public_bytes())
        claim = {
            "version": 1,
            "invite_id": invite_id,
            "name": args.name,
            "signing_public_key": signing_public_key,
            "encryption_public_key": encryption_public_key,
        }
        proof_signature = b64url_encode(
            sign_message(
                keys.signing_private_key,
                canonical_json(claim),
                context=b"vgen-service-enrollment-v1",
            )
        )
        anonymous = GatewayClient(profile)
        try:
            response = anonymous.request(
                "POST",
                "/api/v1/auth/services/enroll",
                json_body={
                    **claim,
                    "secret": secret,
                    "proof_signature": proof_signature,
                },
                auth=False,
            )
        finally:
            anonymous.close()
        service = response["service"]
        enrollment = response["enrollment"]
        _pin_invite_authority(
            invite,
            str(service["workspace_id"]),
            str(enrollment["issuer_user_id"]),
        )
        WorkspaceAuthorityStore().pin_owner(
            workspace_id=invite.authority.workspace_id,
            user_id=invite.authority.user_id,
            root_signing_public_key=invite.authority.root_signing_public_key,
            root_key_id=invite.authority.root_key_id,
            source=invite.authority.source,
        )
        credentials = ServiceCredentials.generate(
            service_id=str(service["id"]),
            workspace_id=str(service["workspace_id"]),
            name=str(service["name"]),
            scopes=list(service["scopes"]),
            enrollment_id=str(enrollment["id"]),
            device_keys=keys,
        )
        account = args.credentials_account or credentials.service_id
        credential_file = args.credentials_file
        credential_store.save(
            account,
            credentials,
            file_path=credential_file,
            overwrite=args.overwrite,
        )
        if args.use:
            profile = profile_store.update_binding(
                profile.name,
                principal_type="service",
                service_id=credentials.service_id,
                service_key_ref=None if credential_file else account,
                service_credentials_file=(
                    str(credential_file.expanduser().resolve()) if credential_file else None
                ),
                default_workspace=credentials.workspace_id,
            )
        session = None
        if service["status"] == "active":
            session = _login_and_store_service_session(profile, credentials)
        _json(
            {
                **credentials.public_info(),
                "status": service["status"],
                "profile": profile.name,
                "profile_bound": args.use,
                "credentials": (
                    str(credential_file.expanduser().resolve())
                    if credential_file
                    else f"os-keyring:{account}"
                ),
                "session_expires_at": session.expires_at if session else None,
                "approval_required": service["status"] == "pending",
            }
        )
        return

    if args.service_action == "use":
        credential_file = args.credentials_file
        account = args.credentials_account or args.service_id
        credentials = credential_store.load(account, file_path=credential_file)
        if credentials.service_id != args.service_id:
            raise ServiceCredentialError(
                "Service credentials do not match the requested Service ID."
            )
        updated = profile_store.update_binding(
            profile.name,
            principal_type="service",
            service_id=credentials.service_id,
            service_key_ref=None if credential_file else account,
            service_credentials_file=(
                str(credential_file.expanduser().resolve()) if credential_file else None
            ),
            default_workspace=credentials.workspace_id,
        )
        _json(
            {
                "profile": updated.name,
                "principal_type": updated.principal_type,
                **credentials.public_info(),
            }
        )
        return

    credentials = _service_credentials_for_profile(profile)
    if args.service_action == "login":
        session = _login_and_store_service_session(profile, credentials)
        _json(
            {
                "profile": profile.name,
                "service_id": credentials.service_id,
                "expires_at": session.expires_at,
            }
        )
    elif args.service_action == "logout":
        ServiceSessionStore().delete(profile.name, credentials.service_id)
        _json(
            {
                "profile": profile.name,
                "service_id": credentials.service_id,
                "logged_out": True,
            }
        )
    elif args.service_action == "show":
        session = ServiceSessionStore().load(profile.name, credentials.service_id)
        _json(
            {
                "profile": profile.name,
                **credentials.public_info(),
                "session_expires_at": session.expires_at if session else None,
            }
        )
    elif args.service_action == "key-sync":
        client = _client(profile.name)
        try:
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            if workspace_id != credentials.workspace_id:
                raise ValueError("Service credentials belong to a different Workspace")
            _json(
                sync_service_workspace_key(
                    client,
                    credentials.device_keys,
                    workspace_id=workspace_id,
                    service_id=credentials.service_id,
                    key_version=args.key_version,
                )
            )
        finally:
            client.close()
    elif args.service_action == "revoke-local":
        ServiceSessionStore().delete(profile.name, credentials.service_id)
        credential_store.delete(
            profile.service_key_ref or credentials.service_id,
            file_path=(
                Path(profile.service_credentials_file) if profile.service_credentials_file else None
            ),
        )
        profile_store.update_binding(
            profile.name,
            principal_type="device",
            service_id=None,
            service_key_ref=None,
            service_credentials_file=None,
        )
        _json(
            {
                "profile": profile.name,
                "service_id": credentials.service_id,
                "local_credentials_removed": True,
                "gateway_principal_revoked": False,
            }
        )
    else:
        raise ValueError("unsupported Service action")


def _grant_approved_enrollment_workspace_key(
    client: GatewayClient,
    identity: DeviceIdentity,
    enrollment: dict[str, Any],
    *,
    verification_code: str,
    admission_already_stored: bool = False,
    owner_user_id: str | None = None,
) -> dict[str, Any] | None:
    """Grant the current Workspace key as part of an approval CLI flow.

    Approval is already committed when this helper runs.  A missing local
    admin key is therefore reported as a resumable follow-up instead of making
    the successful enrollment decision look as if it failed.
    """

    if enrollment.get("state") != "active" or enrollment.get("kind") not in {
        "user",
        "workspace_member",
    }:
        return None
    workspace_id = str(enrollment.get("workspace_id") or "")
    recipient_id = str(enrollment.get("subject_user_id") or "")
    if not workspace_id or not recipient_id:
        return {
            "granted": False,
            "reason": "Gateway did not return the approved User/Workspace binding",
        }
    pinned_owner_user_id = require_local_workspace_owner(
        client, identity, workspace_id=workspace_id
    )
    admission_owner_user_id = str(owner_user_id or enrollment.get("issuer_user_id") or "")
    if not admission_owner_user_id:
        return {"granted": False, "reason": "Enrollment has no Workspace Owner binding"}
    if admission_owner_user_id != pinned_owner_user_id:
        raise ValueError("Enrollment Owner does not match the locally pinned Workspace Owner")
    signed_admission = sign_enrollment_admission(
        identity,
        workspace_id=workspace_id,
        owner_user_id=admission_owner_user_id,
        enrollment=enrollment,
        verification_code=verification_code,
    )
    if not admission_already_stored:
        client.request(
            "POST",
            f"/api/v1/workspaces/{workspace_id}/recipient-admissions",
            json_body={
                "enrollment_id": enrollment["id"],
                "signed_admission": signed_admission,
            },
            idempotency_key=f"workspace-recipient-admission:{enrollment['id']}",
        )
    workspaces = client.request("GET", "/api/v1/workspaces")
    workspace = next(
        (
            item
            for item in workspaces
            if isinstance(item, dict) and str(item.get("id")) == workspace_id
        ),
        None,
    )
    if workspace is None:
        return {"granted": False, "reason": "Workspace is not visible to this admin"}
    key_version = int(workspace.get("key_version") or 1)
    try:
        workspace_key = WorkspaceKeyStore().load(workspace_id, key_version)
    except WorkspaceKeyError:
        return {
            "granted": False,
            "reason": "Workspace key is unavailable on this admin device",
            "next": (
                f"vgen workspace key-grant {recipient_id} --recipient-type user_recovery "
                f"--workspace {workspace_id} --key-version {key_version}"
            ),
        }
    user_grant = grant_workspace_key(
        client,
        identity,
        workspace_id=workspace_id,
        recipient_type="user_recovery",
        recipient_id=recipient_id,
        key_version=key_version,
        workspace_key=workspace_key,
    )
    device_id = str(enrollment.get("subject_id") or "")
    device_grant = (
        grant_workspace_key(
            client,
            identity,
            workspace_id=workspace_id,
            recipient_type="device",
            recipient_id=device_id,
            key_version=key_version,
            workspace_key=workspace_key,
        )
        if device_id
        else None
    )
    return {
        "granted": True,
        "recipient_type": "user_recovery",
        "recipient_id": recipient_id,
        "key_version": key_version,
        "envelope_id": user_grant.get("id"),
        "device_envelope_id": device_grant.get("id") if device_grant else None,
    }


def _read_user_verification_code(value: str | None) -> str:
    if value:
        return value
    if not sys.stdin.isatty():
        raise ValueError("非交互核验必须显式提供 --verification-code")
    code = input("请输入对方通过可信渠道提供的五组 User 核验码: ").strip()
    if not code:
        raise ValueError("User 核验码不能为空")
    return code


def _confirm_legacy_owner_migration(
    *,
    endpoint: str,
    workspace_id: str,
    user_id: str,
    root_key_id: str,
    accept_legacy_tofu: bool,
) -> None:
    print("警告：这是一次不可自动验证的 legacy Workspace Owner TOFU 迁移。", file=sys.stderr)
    print(f"Gateway endpoint: {endpoint}", file=sys.stderr)
    print(f"Workspace: {workspace_id}", file=sys.stderr)
    print(f"User: {user_id}", file=sys.stderr)
    print(f"Owner root key ID: {root_key_id}", file=sys.stderr)
    print(
        "请先独立确认 Gateway 域名、Workspace 和本机恢复身份；本地 pin 写入后不可替换。",
        file=sys.stderr,
    )
    if accept_legacy_tofu:
        return
    if not sys.stdin.isatty():
        raise ValueError(
            "非交互 legacy Owner 迁移必须显式提供 --accept-legacy-tofu"
        )
    confirmation = input(
        f"请输入 {LEGACY_OWNER_MIGRATION_CONFIRMATION} 继续: "
    ).strip()
    if confirmation != LEGACY_OWNER_MIGRATION_CONFIRMATION:
        raise ValueError("legacy Owner 迁移确认词不匹配，未写入任何 pin")


def _wait_for_invite_claim(
    client: GatewayClient,
    *,
    workspace_id: str,
    enrollment_id: str,
    timeout: float,
    interval: float,
) -> dict[str, Any]:
    if timeout <= 0 or interval <= 0:
        raise ValueError("Invite wait timeout and interval must be positive")
    deadline = time.monotonic() + timeout
    while True:
        enrollments = client.request(
            "GET",
            f"/api/v1/workspaces/{workspace_id}/enrollments",
        )
        enrollment = next(
            (
                item
                for item in enrollments
                if isinstance(item, dict) and item.get("id") == enrollment_id
            ),
            None,
        )
        if enrollment is None:
            raise ValueError("Gateway 返回的 Invite 不在当前 Workspace 中")
        state = str(enrollment.get("state") or "")
        if state != "issued":
            return enrollment
        if time.monotonic() >= deadline:
            raise ValueError(
                "等待对方领取 Invite 超时；对方领取后可运行 "
                f"vgen workspace key-grant-enrollment {enrollment_id}"
            )
        time.sleep(interval)


def _workspace_command(args: argparse.Namespace) -> None:
    client = _client(args.profile)
    try:
        profile = client.profile
        if args.workspace_action == "create":
            workspace = client.create_workspace(
                {"name": args.name, "founder_broker_id": args.broker_id}
            )
            _, identity = _profile_and_identity(profile.name)
            WorkspaceAuthorityStore().pin(
                workspace_id=str(workspace["id"]),
                user_id=str(workspace["owner_user_id"]),
                root_signing_public_key=identity.root_signing_public_key,
                root_key_id=identity.root_key_id,
                source="workspace_creation",
            )
            WorkspaceAuthorityStore().pin_owner(
                workspace_id=str(workspace["id"]),
                user_id=str(workspace["owner_user_id"]),
                root_signing_public_key=identity.root_signing_public_key,
                root_key_id=identity.root_key_id,
                source="workspace_creation",
            )
            workspace["key_envelopes"] = initialize_workspace_keys(client, identity, workspace)
            if args.use:
                ProfileStore().update_binding(profile.name, default_workspace=workspace["id"])
            _json(workspace)
        elif args.workspace_action == "list":
            _json(client.request("GET", "/api/v1/workspaces"))
        elif args.workspace_action in {"member-list", "user-list"}:
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            _json(
                client.request(
                    "GET",
                    f"/api/v1/workspaces/{workspace_id}/members",
                    params={"include_revoked": True} if args.include_revoked else None,
                )
            )
        elif args.workspace_action == "pool-create":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            policy = json.loads(args.policy) if args.policy else {}
            _json(client.create_pool(workspace_id, {"name": args.name, "policy": policy}))
        elif args.workspace_action == "pool-list":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            _json(client.request("GET", f"/api/v1/workspaces/{workspace_id}/pools"))
        elif args.workspace_action == "owner-migrate":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            if not profile.user_id:
                raise ValueError("profile is not bound to a User")
            _, identity = _profile_and_identity(profile.name)
            try:
                owner_user_id = require_local_workspace_owner(
                    client, identity, workspace_id=workspace_id
                )
            except LegacyOwnerMigrationRequired:
                _confirm_legacy_owner_migration(
                    endpoint=profile.endpoint,
                    workspace_id=workspace_id,
                    user_id=profile.user_id,
                    root_key_id=identity.root_key_id,
                    accept_legacy_tofu=args.accept_legacy_tofu,
                )
                result = migrate_legacy_workspace_owner(
                    client,
                    identity,
                    workspace_id=workspace_id,
                )
            else:
                pin = WorkspaceAuthorityStore().load_owner(workspace_id)
                result = {
                    "workspace_id": workspace_id,
                    "owner_user_id": owner_user_id,
                    "owner_root_key_id": identity.root_key_id,
                    "migrated": False,
                    "source": pin.source if pin is not None else "verified_genesis_admission",
                }
            _json(result)
        elif args.workspace_action == "key-sync":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            if not profile.user_id:
                raise ValueError("profile is not bound to a User")
            _, identity = _profile_and_identity(profile.name)
            _json(
                sync_workspace_key(
                    client,
                    identity,
                    workspace_id=workspace_id,
                    user_id=profile.user_id,
                    key_version=args.key_version,
                )
            )
        elif args.workspace_action == "key-grant":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            _, identity = _profile_and_identity(profile.name)
            key_version = args.key_version or 1
            _json(
                grant_workspace_key(
                    client,
                    identity,
                    workspace_id=workspace_id,
                    recipient_type=args.recipient_type,
                    recipient_id=args.recipient_id,
                    key_version=key_version,
                    workspace_key=WorkspaceKeyStore().load(workspace_id, key_version),
                )
            )
        elif args.workspace_action == "key-grant-enrollment":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            enrollments = client.request(
                "GET",
                f"/api/v1/workspaces/{workspace_id}/enrollments",
            )
            enrollment = next(
                (
                    item
                    for item in enrollments
                    if isinstance(item, dict) and item.get("id") == args.enrollment_id
                ),
                None,
            )
            if enrollment is None:
                raise ValueError("这个 Workspace 中找不到指定的 Enrollment")
            if enrollment.get("state") != "active":
                raise ValueError(
                    "Enrollment 尚未激活；invite_approval 请先运行 workspace decide --approve"
                )
            _, identity = _profile_and_identity(profile.name)
            key_grant = _grant_approved_enrollment_workspace_key(
                client,
                identity,
                enrollment,
                verification_code=_read_user_verification_code(
                    getattr(args, "verification_code", None)
                ),
                owner_user_id=profile.user_id,
            )
            if key_grant is None:
                raise ValueError("这个 Enrollment 不对应 User Workspace 成员")
            _json(
                {
                    "enrollment_id": args.enrollment_id,
                    "workspace_id": workspace_id,
                    "workspace_key_grant": key_grant,
                }
            )
        elif args.workspace_action == "key-rotate":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            _, identity = _profile_and_identity(profile.name)
            _json(
                rotate_workspace_key(
                    client,
                    identity,
                    workspace_id=workspace_id,
                    expected_key_version=args.expected_key_version,
                )
            )
        elif args.workspace_action == "authority-pin":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            pin = WorkspaceAuthorityStore().pin(
                workspace_id=workspace_id,
                user_id=args.user_id,
                root_signing_public_key=args.root_signing_public_key,
                root_key_id=args.root_key_id,
                source="explicit_out_of_band",
            )
            _json(asdict(pin))
        elif args.workspace_action == "invite":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            _, identity = _profile_and_identity(profile.name)
            if args.kind in {"user", "workspace_member", "service"}:
                require_local_workspace_owner(
                    client, identity, workspace_id=workspace_id
                )
            result = client.request(
                "POST",
                f"/api/v1/workspaces/{workspace_id}/invites",
                json_body={
                    "kind": args.kind,
                    "method": args.method,
                    "relationship": args.relationship,
                    "scopes": args.scope,
                    "subject_key_fingerprint": args.subject_key_fingerprint,
                    "ttl_seconds": args.ttl,
                },
            )
            if not profile.user_id:
                raise ValueError("profile is not bound to a User")
            enrollment = result.get("enrollment") or {}
            if (
                str(enrollment.get("workspace_id")) != workspace_id
                or str(enrollment.get("issuer_user_id")) != profile.user_id
            ):
                raise ValueError("Gateway Invite response does not match the local issuer")
            invite_uri = decorate_invite_uri(
                str(result["invite_uri"]),
                workspace_id=workspace_id,
                issuer_user_id=profile.user_id,
                identity=identity.root_keys,
            )
            # stdout intentionally contains only the complete URI so it can be
            # copied through a trusted channel without status text.  The URI
            # must never be written to application logs.
            print(invite_uri, flush=True)
            if args.wait:
                enrollment = _wait_for_invite_claim(
                    client,
                    workspace_id=workspace_id,
                    enrollment_id=str(result["enrollment"]["id"]),
                    timeout=args.timeout,
                    interval=args.wait_interval,
                )
                if enrollment.get("state") == "pending":
                    print(
                        "对方已领取邀请，正在等待批准。请运行：\n"
                        f"vgen workspace decide {enrollment['id']} --approve "
                        "--verification-code <五组核验码>",
                        file=sys.stderr,
                    )
                elif enrollment.get("state") == "active":
                    key_grant = _grant_approved_enrollment_workspace_key(
                        client,
                        identity,
                        enrollment,
                        verification_code=_read_user_verification_code(
                            getattr(args, "verification_code", None)
                        ),
                        owner_user_id=profile.user_id,
                    )
                    if key_grant is not None and key_grant.get("granted"):
                        print("对方已加入，Workspace 加密密钥已自动发放。", file=sys.stderr)
                    elif key_grant is not None:
                        print(
                            "对方已加入，但加密密钥尚未发放："
                            f"{key_grant.get('reason') or 'unknown reason'}",
                            file=sys.stderr,
                        )
        elif args.workspace_action == "apply":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            _, identity = _profile_and_identity(profile.name)
            application_id = new_id("application")
            claim, proof_signature = identity_registration_claim(
                identity,
                invite_id=application_id,
                display_name=(args.display_name or getpass.getuser() or "VGen User"),
                device_name=(args.device_name or identity.alias or "Device"),
            )
            _json(
                client.request(
                    "POST",
                    "/api/v1/applications",
                    json_body={
                        "application_id": application_id,
                        "workspace_id": workspace_id,
                        "pool_id": args.pool,
                        "kind": args.kind,
                        "relationship": args.relationship,
                        "claim": claim,
                        "proof_signature": proof_signature,
                    },
                )
            )
        elif args.workspace_action == "decide":
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            enrollments = client.request(
                "GET", f"/api/v1/workspaces/{workspace_id}/enrollments"
            )
            enrollment = next(
                (
                    item
                    for item in enrollments
                    if isinstance(item, dict) and item.get("id") == args.enrollment_id
                ),
                None,
            )
            if enrollment is None:
                raise ValueError("这个 Workspace 中找不到指定的 Enrollment")
            signed_admission = None
            verification_code = None
            if args.approve and enrollment.get("kind") in {"user", "workspace_member"}:
                verification_code = _read_user_verification_code(
                    getattr(args, "verification_code", None)
                )
                _, identity = _profile_and_identity(profile.name)
                require_local_workspace_owner(
                    client, identity, workspace_id=workspace_id
                )
                signed_admission = sign_enrollment_admission(
                    identity,
                    workspace_id=workspace_id,
                    owner_user_id=str(profile.user_id or ""),
                    enrollment=enrollment,
                    verification_code=verification_code,
                )
            result = client.request(
                "POST",
                f"/api/v1/enrollments/{args.enrollment_id}/decision",
                json_body={
                    "approve": args.approve,
                    "signed_admission": signed_admission,
                },
            )
            if args.approve and verification_code is not None:
                _, identity = _profile_and_identity(profile.name)
                key_grant = _grant_approved_enrollment_workspace_key(
                    client,
                    identity,
                    result,
                    verification_code=verification_code,
                    admission_already_stored=True,
                    owner_user_id=profile.user_id,
                )
                if key_grant is not None:
                    result["workspace_key_grant"] = key_grant
            _json(result)
        elif args.workspace_action in {"enrollment-list", "allocation-list", "audit"}:
            workspace_id = args.workspace or profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            if args.workspace_action == "enrollment-list":
                _json(
                    client.request(
                        "GET",
                        f"/api/v1/workspaces/{workspace_id}/enrollments",
                        params={"state": args.state} if args.state else None,
                    )
                )
            elif args.workspace_action == "allocation-list":
                _json(
                    client.request(
                        "GET",
                        f"/api/v1/workspaces/{workspace_id}/worker-allocations",
                    )
                )
            else:
                _json(
                    client.request(
                        "GET",
                        f"/api/v1/workspaces/{workspace_id}/audit",
                        params={"limit": args.limit},
                    )
                )
    finally:
        client.close()


_MAINTENANCE_INTENT_TTL_SECONDS = 24 * 60 * 60
_MAINTENANCE_TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled", "expired"})


def _maintenance_broker_id(client: GatewayClient, requested: str | None) -> str:
    if client.profile.principal_type != "device":
        raise ValueError("Worker maintenance requires a User Device profile")
    broker_id = requested or client.profile.home_broker_id
    if not broker_id:
        raise ValueError(
            "no Home Broker is selected; run `vgen setup` or pass --broker explicitly"
        )
    return str(broker_id)


def _select_owned_worker(client: GatewayClient, selector: str | None) -> dict[str, Any]:
    workers = client.request("GET", "/api/v1/workers")
    if not isinstance(workers, list):
        raise ValueError("Gateway returned an invalid Worker list")
    active = [item for item in workers if isinstance(item, dict) and item.get("status") != "revoked"]
    if selector:
        matches = [
            worker
            for worker in active
            if selector in {str(worker.get("id") or ""), str(worker.get("name") or "")}
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise ValueError(f"no owned Worker matches: {selector}")
        raise ValueError(f"more than one owned Worker is named: {selector}; use its Worker ID")
    if len(active) == 1:
        return active[0]
    if not active:
        raise ValueError("this User has no active Worker")
    choices = ", ".join(
        f"{worker.get('name') or 'unnamed'} ({worker.get('id')})" for worker in active
    )
    raise ValueError(f"choose a Worker with --worker; available Workers: {choices}")


def _ensure_broker_manages_worker(
    client: GatewayClient,
    worker: Mapping[str, Any],
    broker_id: str,
) -> dict[str, Any]:
    manager = worker.get("manager_broker_id")
    if manager == broker_id:
        return dict(worker)
    if manager:
        raise ValueError(
            "the selected Worker is managed by another Broker; use `vgen worker manager-set` "
            "explicitly before changing its maintenance authority"
        )
    raise ValueError(
        "the selected Worker has no manager Broker; bind it explicitly with "
        "`vgen worker manager-set` before authorizing remote maintenance"
    )


def _maintenance_authorization(
    identity: DeviceIdentity,
    *,
    worker_id: str,
    broker_id: str,
    spec: Mapping[str, Any],
    issued_at: int | None = None,
) -> dict[str, Any]:
    issued = int(time.time()) if issued_at is None else int(issued_at)
    action = str(spec.get("kind") or "")
    payload = build_maintenance_intent_payload(
        worker_id=worker_id,
        broker_id=broker_id,
        kind=action,
        spec=spec,
        device_id=identity.device_id,
        issued_at=issued,
        expires_at=issued + _MAINTENANCE_INTENT_TTL_SECONDS,
        nonce=uuid.uuid4().hex,
    )
    return sign_maintenance_intent(identity.device_keys, identity.certificate, payload)


def _wait_for_maintenance(
    client: GatewayClient,
    job_id: str,
    *,
    interval: float,
    timeout: float,
) -> dict[str, Any]:
    if interval <= 0 or timeout <= 0:
        raise ValueError("maintenance wait interval and timeout must be positive")
    deadline = time.monotonic() + timeout
    last_state: str | None = None
    while True:
        job = client.get_worker_maintenance(job_id)
        if not isinstance(job, dict):
            raise ValueError("Gateway returned an invalid maintenance job")
        state = str(job.get("state") or "unknown")
        if state != last_state:
            print(f"维护任务状态：{state}", file=sys.stderr)
            last_state = state
        if state in _MAINTENANCE_TERMINAL_STATES:
            return job
        if time.monotonic() >= deadline:
            raise TimeoutError("maintenance wait timed out")
        time.sleep(interval)


def _raise_for_unsuccessful_maintenance(job: Mapping[str, Any]) -> None:
    """Turn a terminal maintenance result into the stable CLI exit contract."""

    state = str(job.get("state") or "")
    if state == "succeeded":
        return
    result = job.get("result")
    raw_code = result.get("error_code") if isinstance(result, Mapping) else None
    if isinstance(raw_code, int) and not isinstance(raw_code, bool):
        code = raw_code
    elif state == "expired":
        code = int(ErrorCode.MAINTENANCE_LEASE_LOST)
    elif state == "cancelled":
        code = int(ErrorCode.WORKER_MAINTENANCE_STATE_CONFLICT)
    else:
        code = int(ErrorCode.INTERNAL_ERROR)
    try:
        spec = get_error_spec(code)
    except ValueError:
        spec = get_error_spec(ErrorCode.INTERNAL_ERROR)
        code = int(spec.code)
    raise VgenClientError(
        code,
        spec.code.name,
        spec.message,
        retry_action=spec.retry_action.value,
    )


def _maintenance_upload_ticket(
    value: Mapping[str, Any],
    *,
    expected_size: int,
    expected_sha256: str,
) -> TransferTicket:
    max_bytes = value.get("max_bytes")
    if max_bytes is not None and (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes < expected_size
    ):
        raise ValueError("Gateway maintenance upload ticket is smaller than the update wheel")
    headers = value.get("headers") or {}
    if not isinstance(headers, Mapping):
        raise ValueError("Gateway maintenance upload ticket headers are invalid")
    try:
        return TransferTicket(
            url=str(value["url"]),
            method=str(value["method"]),
            headers={str(key): str(item) for key, item in headers.items()},
            endpoint=(None if value.get("endpoint") is None else str(value["endpoint"])),
            credentials={
                str(key): str(item)
                for key, item in dict(value.get("credentials") or {}).items()
            },
            expires_at=(None if value.get("expires_at") is None else float(value["expires_at"])),
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            media_type="application/octet-stream",
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Gateway returned an invalid maintenance upload ticket") from exc


def _worker_capability_model_digests(worker: Mapping[str, Any]) -> set[str]:
    capabilities = worker.get("capabilities")
    if not isinstance(capabilities, Mapping):
        return set()
    candidates: list[Any] = [capabilities.get("model_digests")]
    executors = capabilities.get("executors")
    if isinstance(executors, list):
        for executor in executors:
            if not isinstance(executor, Mapping):
                continue
            nested = executor.get("capabilities")
            if isinstance(nested, Mapping):
                candidates.append(nested.get("model_digests"))
    result: set[str] = set()
    for values in candidates:
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str):
                continue
            normalized = value.lower()
            if not normalized.startswith("sha256:"):
                normalized = "sha256:" + normalized
            if len(normalized) == 71 and all(character in "0123456789abcdef" for character in normalized[7:]):
                result.add(normalized)
    return result


def _accepted_model_licenses(
    models: list[Any],
    accepted: list[str],
    *,
    accepted_at: int,
) -> list[dict[str, Any]]:
    required = {str(model.license) for model in models}
    supplied = set(accepted)
    unexpected = supplied - required
    if unexpected:
        raise ValueError(
            "--accept-license contains a license not required by the selected models: "
            + ", ".join(sorted(unexpected))
        )
    missing = sorted(required - supplied)
    if missing and not sys.stdin.isatty():
        flags = " ".join(f"--accept-license {item}" for item in missing)
        raise ValueError(f"explicit model license acceptance is required: {flags}")
    for license_id in missing:
        print(f"模型许可证：{license_id}", file=sys.stderr)
        confirmation = input(f"请输入完整许可证标识 `{license_id}` 以确认接受：").strip()
        if confirmation != license_id:
            raise ValueError(f"license acceptance was not confirmed for {license_id}")
        supplied.add(license_id)
    acceptances: list[dict[str, Any]] = []
    for model in models:
        revision = str(model.revision or "")
        if not revision:
            raise ValueError("model installation requires an immutable model revision")
        acceptances.append(
            {
                "model_digest": "sha256:" + str(model.sha256),
                "license_id": str(model.license),
                "revision": revision,
                "accepted_at": accepted_at,
            }
        )
    return acceptances


def _create_maintenance_job(
    client: GatewayClient,
    identity: DeviceIdentity,
    *,
    broker_id: str,
    worker: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    worker_id = str(worker.get("id") or "")
    if not worker_id:
        raise ValueError("Gateway Worker response has no Worker ID")
    authorization = _maintenance_authorization(
        identity,
        worker_id=worker_id,
        broker_id=broker_id,
        spec=spec,
    )
    created = client.create_worker_maintenance(
        broker_id=broker_id,
        worker_id=worker_id,
        spec=spec,
        authorization=authorization,
        idempotency_key=f"maintenance:{worker_id}:{spec['kind']}:{uuid.uuid4().hex}",
    )
    if not isinstance(created, dict) or not created.get("id"):
        raise ValueError("Gateway returned an invalid maintenance job")
    return created


def _apply_worker_update(
    client: GatewayClient,
    args: argparse.Namespace,
    wheel: Path,
) -> dict[str, Any]:
    from .worker_bundle import inspect_worker_update_wheel

    broker_id = _maintenance_broker_id(client, args.broker)
    worker = _select_owned_worker(client, args.worker)
    worker = _ensure_broker_manages_worker(client, worker, broker_id)
    artifact = inspect_worker_update_wheel(wheel)
    capabilities = worker.get("capabilities")
    current_version = (
        capabilities.get("worker_runtime_version")
        if isinstance(capabilities, Mapping)
        else None
    )
    if isinstance(current_version, str):
        try:
            current = Version(current_version)
            target = Version(artifact.version)
        except InvalidVersion as exc:
            raise ValueError("Worker reported an invalid runtime version") from exc
        if current == target:
            return {
                "worker_id": worker["id"],
                "state": "already_up_to_date",
                "current_version": current_version,
                "target_version": artifact.version,
            }
        if current > target:
            raise ValueError(
                f"Worker {current_version} is newer than stable {artifact.version}; "
                "refusing to downgrade"
            )
    spec = {
        "kind": "worker_update",
        "target_version": artifact.version,
        "artifact_sha256": artifact.sha256,
        "artifact_size": artifact.size_bytes,
        "apply": "on_idle",
    }
    _, identity = _profile_and_identity(client.profile.name)
    created = _create_maintenance_job(
        client,
        identity,
        broker_id=broker_id,
        worker=worker,
        spec=spec,
    )
    upload_ticket = created.get("upload_ticket")
    if isinstance(upload_ticket, Mapping):
        print(f"正在上传 Worker {artifact.version} 更新包…", file=sys.stderr)
        ticket = _maintenance_upload_ticket(
            upload_ticket,
            expected_size=artifact.size_bytes,
            expected_sha256=artifact.sha256,
        )
        adapter = (
            OssStsArtifactAdapter()
            if ticket.url.startswith("oss://")
            else HttpArtifactAdapter()
        )
        adapter.upload(ticket, artifact.path)
        committed = client.commit_worker_maintenance(str(created["id"]))
        if not isinstance(committed, dict):
            raise ValueError("Gateway returned an invalid committed maintenance job")
    elif created.get("state") in {"queued", "leased", "running", "restarting"}:
        # A prior invocation may already have uploaded and committed the same
        # digest. The Gateway deduplicates that active job and must not mint a
        # second upload capability.
        committed = created
    else:
        raise ValueError("Gateway update job has no upload ticket")
    result = (
        _wait_for_maintenance(
            client,
            str(committed.get("id") or created["id"]),
            interval=args.interval,
            timeout=args.timeout,
        )
        if args.wait
        else committed
    )
    if args.wait:
        _raise_for_unsuccessful_maintenance(result)
    return result


def _broker_command(args: argparse.Namespace) -> None:
    if args.broker_action == "local-status":
        from .macos_broker_service import inspect_macos_broker_service

        value = inspect_macos_broker_service()
        value["cli_version"] = __version__
        value["upgrade_available"] = _upgrade_available(value.get("runtime_version"))
        _json(value)
        return
    if args.broker_action == "service-refresh":
        from .macos_broker_service import (
            inspect_macos_broker_service,
            install_macos_broker_service,
        )

        existing_service = inspect_macos_broker_service()
        service_profile = existing_service.get("profile")
        selected_profile = args.profile or (
            str(service_profile) if isinstance(service_profile, str) and service_profile else None
        )
        profile = ProfileStore().get(selected_profile)
        if not profile.home_broker_id or not profile.home_broker_device_id:
            _json(
                {
                    "skipped": True,
                    "reason": "profile_has_no_home_broker",
                    "profile": profile.name,
                }
            )
            return
        service = install_macos_broker_service(
            profile_name=profile.name,
            broker_id=profile.home_broker_id,
            broker_device_id=profile.home_broker_device_id,
        )
        if not service.loaded:
            raise ValueError(service.error or "Home Broker service could not be loaded")
        value = inspect_macos_broker_service()
        value["cli_version"] = __version__
        _json(value)
        return
    if args.broker_action == "serve":
        from vgen.broker.main import run_broker

        run_broker(args)
        return
    client = _client(args.profile)
    try:
        if args.broker_action == "create":
            identity = DeviceIdentityStore().load(client.profile.key_ref or "default")
            _json(
                client.request(
                    "POST",
                    "/api/v1/brokers",
                    json_body={
                        "name": args.name,
                        "device_id": client.profile.device_id or identity.device_id,
                    },
                )
            )
        elif args.broker_action in {"list", "status"}:
            brokers = client.request("GET", "/api/v1/brokers")
            if args.broker_action == "status" and isinstance(brokers, list):
                for broker in brokers:
                    for device in broker.get("devices", []):
                        runtime_version = device.get("runtime_version")
                        device["upgrade_available"] = _upgrade_available(runtime_version)
                _json(brokers)
            else:
                _json(brokers)
        elif args.broker_action == "device":
            _json(
                client.request(
                    "POST",
                    f"/api/v1/brokers/{args.broker_id}/devices",
                    json_body={"device_id": args.device_id},
                    idempotency_key=f"broker-device:{args.broker_id}:{args.device_id}",
                )
            )
        elif args.broker_action == "worker-update":
            _json(_apply_worker_update(client, args, args.wheel))
        elif args.broker_action == "model-install":
            broker_id = _maintenance_broker_id(client, args.broker)
            worker = _select_owned_worker(client, args.worker)
            worker = _ensure_broker_manages_worker(client, worker, broker_id)
            manifest, _, digest = _resolve_workflow(args.workflow)
            executor_type = str(worker.get("executor_type") or "")
            variants = [
                variant for variant in manifest.variants if variant.executor_type == executor_type
            ]
            if not variants:
                raise ValueError(
                    f"workflow has no {executor_type or 'selected Worker'} executor variant"
                )
            if len(variants) > 1:
                raise ValueError("workflow has more than one matching executor variant")
            installed_digests = _worker_capability_model_digests(worker)
            missing = [
                model
                for model in variants[0].models
                if "sha256:" + model.sha256 not in installed_digests
            ]
            if not missing:
                _json(
                    {
                        "worker_id": worker["id"],
                        "workflow": f"{manifest.id}@{manifest.version}",
                        "state": "already_satisfied",
                        "missing_models": 0,
                    }
                )
                return
            gated = [model.filename for model in missing if model.gated]
            if gated:
                raise ValueError(
                    "gated models require Worker-local credentials and cannot be installed by a Broker: "
                    + ", ".join(gated)
                )
            total_bytes = sum(int(model.size) for model in missing)
            print(
                f"将安装 {len(missing)} 个缺失模型，共 {total_bytes / 1_000_000_000:.2f} GB。",
                file=sys.stderr,
            )
            print(
                "需要接受的模型许可证：" + "、".join(sorted({model.license for model in missing})),
                file=sys.stderr,
            )
            accepted_at = int(time.time())
            acceptances = _accepted_model_licenses(
                missing,
                args.accept_license,
                accepted_at=accepted_at,
            )
            spec = {
                "kind": "model_install",
                "workflow_ref": f"{manifest.id}@{manifest.version}",
                "workflow_digest": f"sha256:{digest}",
                "model_digests": ["sha256:" + model.sha256 for model in missing],
                "license_acceptances": acceptances,
            }
            _, identity = _profile_and_identity(client.profile.name)
            created = _create_maintenance_job(
                client,
                identity,
                broker_id=broker_id,
                worker=worker,
                spec=spec,
            )
            result = (
                _wait_for_maintenance(
                    client,
                    str(created["id"]),
                    interval=args.interval,
                    timeout=args.timeout,
                )
                if args.wait
                else created
            )
            _json(result)
            if args.wait:
                _raise_for_unsuccessful_maintenance(result)
        elif args.broker_action == "maintenance-list":
            worker = _select_owned_worker(client, args.worker)
            _json(client.list_worker_maintenance(str(worker["id"])))
        elif args.broker_action == "maintenance-show":
            _json(client.get_worker_maintenance(args.job_id))
        elif args.broker_action == "maintenance-cancel":
            _json(client.cancel_worker_maintenance(args.job_id))
    finally:
        client.close()


def _create_worker_invite(
    client: GatewayClient,
    owner_identity: DeviceIdentity,
    args: argparse.Namespace,
) -> tuple[str, str, str]:
    if not args.name.strip():
        raise ValueError("Worker name is required")
    if args.rate < 0:
        raise ValueError("Worker rate cannot be negative")
    if not 60 <= args.ttl <= 86_400:
        raise ValueError("Worker Invite lifetime must be between 60 and 86400 seconds")
    if args.interval <= 0 or args.timeout <= 0:
        raise ValueError("Worker wait interval and timeout must be positive")
    workspace_id = client.profile.default_workspace
    if not workspace_id or not client.profile.user_id:
        raise ValueError("the selected profile has no Workspace/User binding")
    pool_id = _resolve_pool_id(client, workspace_id=workspace_id, requested=args.pool)
    response = client.request(
        "POST",
        f"/api/v1/workspaces/{workspace_id}/worker-invites",
        json_body={
            "method": "invite_approval",
            "pool_id": pool_id,
            "name": args.name,
            "executor_type": "comfyui",
            "executor_version": "1.1.0",
            "capacity": 1,
            "manager_broker_id": (
                args.manager_broker or getattr(client.profile, "home_broker_id", None)
            ),
            "rate_microtokens_per_second": args.rate,
            "ttl_seconds": args.ttl,
        },
        idempotency_key=f"worker-add:{uuid.uuid4()}",
    )
    enrollment = response.get("enrollment") if isinstance(response, dict) else None
    if (
        not isinstance(enrollment, dict)
        or str(enrollment.get("workspace_id")) != workspace_id
        or str(enrollment.get("issuer_user_id")) != client.profile.user_id
        or str(enrollment.get("pool_id")) != pool_id
    ):
        raise ValueError("Gateway returned an invalid Worker Invite")
    invite_uri = decorate_invite_uri(
        str(response["invite_uri"]),
        workspace_id=workspace_id,
        issuer_user_id=str(client.profile.user_id),
        identity=owner_identity.root_keys,
    )
    return str(enrollment["id"]), workspace_id, invite_uri


def _approve_worker_enrollment(
    client: GatewayClient,
    owner_identity: DeviceIdentity,
    *,
    enrollment_id: str,
    workspace_id: str,
    approval_code: str,
) -> dict[str, Any]:
    from .worker_enrollment import require_pending_worker_claim

    issuer_user_id = client.profile.user_id
    if not issuer_user_id:
        raise ValueError("the selected profile has no User binding")
    pending = client.request("GET", f"/api/v1/worker-enrollments/{enrollment_id}")
    claim = require_pending_worker_claim(
        pending,
        enrollment_id=enrollment_id,
        workspace_id=workspace_id,
        issuer_user_id=issuer_user_id,
        approval_code=approval_code,
    )
    allocation = pending.get("allocation")
    if not isinstance(allocation, dict):
        raise ValueError("Gateway returned no provisional Worker allocation")
    owner_certificate = sign_key_manifest(
        owner_identity.root_keys,
        {
            "version": 1,
            "kind": "vgen-worker-owner-certificate",
            "owner_root_key_id": owner_identity.root_key_id,
            "worker_key_id": claim["worker_key_id"],
            "worker_signing_public_key": claim["signing_public_key"],
            "worker_encryption_public_key": claim["encryption_public_key"],
            "issued_at": int(time.time()),
        },
    )
    try:
        proof_payload = build_allocation_proof_payload(
            allocation_id=str(allocation["id"]),
            workspace_id=str(allocation["workspace_id"]),
            pool_id=str(allocation["pool_id"]),
            worker_id=str(allocation["worker_id"]),
            worker_signing_public_key=str(claim["signing_public_key"]),
            worker_encryption_public_key=str(claim["encryption_public_key"]),
            worker_certificate=owner_certificate,
            owner_consent_at=float(allocation["owner_consent_at"]),
            approver_root_key_id=owner_identity.root_key_id,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Gateway returned an invalid provisional Worker allocation") from exc
    return client.request(
        "POST",
        f"/api/v1/worker-enrollments/{enrollment_id}/decision",
        json_body={
            "approve": True,
            "owner_certificate": json.dumps(owner_certificate, separators=(",", ":")),
            "allocation_proof": sign_allocation_proof(owner_identity.root_keys, proof_payload),
        },
        idempotency_key=f"worker-enrollment-approve:{enrollment_id}",
    )


def _worker_command(args: argparse.Namespace) -> None:
    if args.worker_action == "serve":
        from vgen.worker.main import run_entrypoint as run_worker

        worker_args = ["serve"]
        for name in (
            "gateway_url",
            "worker_id",
            "identity_account",
            "executor",
            "comfy_url",
        ):
            value = getattr(args, name)
            if value is not None:
                worker_args.extend([f"--{name.replace('_', '-')}", str(value)])
        for name in (
            "identity_file",
            "credentials_file",
            "session_token_file",
            "comfy_output_dir",
            "comfy_model_root",
            "comfy_policy_file",
            "work_root",
        ):
            value = getattr(args, name)
            if value is not None:
                worker_args.extend([f"--{name.replace('_', '-')}", str(value)])
        for root in args.local_artifact_root:
            worker_args.extend(["--local-artifact-root", str(root)])
        worker_args.extend(["--lease-ttl", str(args.lease_ttl)])
        worker_args.extend(["--interval", str(args.interval)])
        for name in ("credentials_keyring", "announce", "allow_http", "once", "json"):
            if getattr(args, name):
                worker_args.append(f"--{name.replace('_', '-')}")
        code = run_worker(worker_args)
        if code:
            raise SystemExit(code)
        return

    client = _client(args.profile)
    try:
        if args.worker_action == "upgrade":
            print("正在检查 stable Worker 版本并校验发布包…", file=sys.stderr)
            with stable_worker_wheel(client.profile) as (version, wheel):
                print(f"已验证 stable Worker {version}，准备远程更新…", file=sys.stderr)
                _json(_apply_worker_update(client, args, wheel))
        elif args.worker_action == "add":
            _, owner_identity = _profile_and_identity(client.profile.name)
            enrollment_id, workspace_id, invite_uri = _create_worker_invite(
                client, owner_identity, args
            )
            print("\n在 Windows 运行统一 Worker 安装器，然后把下面的一次性 Invite 粘贴到隐藏输入框：\n")
            print(invite_uri)
            print("\nInvite 不要发送到群聊、截图或命令参数。正在等待 Windows 领取……")
            deadline = time.monotonic() + args.timeout
            while True:
                pending = client.request(
                    "GET", f"/api/v1/worker-enrollments/{enrollment_id}"
                )
                enrollment = pending.get("enrollment") if isinstance(pending, dict) else None
                state = str(enrollment.get("state") or "") if isinstance(enrollment, dict) else ""
                if state == "pending" and isinstance(enrollment.get("claim"), dict):
                    break
                if state in {"active", "expired", "rejected", "revoked"}:
                    raise ValueError(f"Worker enrollment finished unexpectedly with state '{state}'")
                if time.monotonic() >= deadline:
                    raise TimeoutError("等待 Windows 领取 Worker Invite 超时；请重新运行 vgen worker add")
                time.sleep(min(args.interval, max(0.0, deadline - time.monotonic())))
            print("\n✓ Windows 已生成本机 Worker 密钥并领取 Invite。")
            code = input("请输入 Windows 显示的完整验证码以批准接入: ").strip()
            if not code:
                raise ValueError("验证码不能为空；Worker 尚未批准")
            result = _approve_worker_enrollment(
                client,
                owner_identity,
                enrollment_id=enrollment_id,
                workspace_id=workspace_id,
                approval_code=code,
            )
            print("\n✓ 验证码一致，Worker 已批准。Windows 将自动继续安装和启动。")
            _json(result)
        elif args.worker_action == "manager-set":
            broker_id = _maintenance_broker_id(client, args.broker)
            worker = _select_owned_worker(client, args.worker)
            manager = worker.get("manager_broker_id")
            if manager == broker_id:
                _json(worker)
            else:
                _json(client.set_worker_manager(str(worker["id"]), broker_id))
        elif args.worker_action == "list":
            params = {"workspace_id": args.workspace} if args.workspace else None
            _json(client.request("GET", "/api/v1/workers", params=params))
        elif args.worker_action == "offer":
            _json(
                client.request(
                    "POST",
                    f"/api/v1/workers/{args.worker_id}/offer",
                    json_body={"pool_id": args.pool},
                    idempotency_key=f"worker-offer:{args.worker_id}:{args.pool}",
                )
            )
        elif args.worker_action == "approve-allocation":
            allocation = client.request("GET", f"/api/v1/worker-allocations/{args.allocation_id}")
            worker = allocation.get("worker")
            if not isinstance(worker, dict):
                raise ValueError("Gateway allocation response has no Worker key manifest")
            _, identity = _profile_and_identity(args.profile)
            proof_payload = build_allocation_proof_payload(
                allocation_id=str(allocation["id"]),
                workspace_id=str(allocation["workspace_id"]),
                pool_id=str(allocation["pool_id"]),
                worker_id=str(allocation["worker_id"]),
                worker_signing_public_key=str(worker["signing_public_key"]),
                worker_encryption_public_key=str(worker["encryption_public_key"]),
                worker_certificate=worker["certificate"],
                owner_consent_at=float(allocation["owner_consent_at"]),
                approver_root_key_id=identity.root_key_id,
            )
            _json(
                client.request(
                    "POST",
                    f"/api/v1/worker-allocations/{args.allocation_id}/approve",
                    json_body={"proof": sign_allocation_proof(identity.root_keys, proof_payload)},
                    idempotency_key=(
                        f"allocation-approve:{args.allocation_id}:"
                        f"{proof_payload['owner_consent_at_ms']}"
                    ),
                )
            )
        elif args.worker_action in {"leave", "revoke"}:
            force = args.worker_action == "revoke" or args.force
            suffix = "revoke" if args.worker_action == "revoke" else "leave"
            _json(
                client.request(
                    "POST",
                    f"/api/v1/workers/{args.worker_id}/{suffix}",
                    json_body={} if suffix == "revoke" else {"force": force},
                    idempotency_key=f"worker-{suffix}:{args.worker_id}",
                )
            )
        elif args.worker_action == "rate-propose":
            workspace_id = args.workspace or client.profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            _json(
                client.request(
                    "POST",
                    f"/api/v1/workers/{args.worker_id}/rates",
                    json_body={
                        "workspace_id": workspace_id,
                        "rate_microtokens_per_second": args.rate,
                    },
                    idempotency_key=(
                        f"worker-rate:{args.worker_id}:{workspace_id}:"
                        f"{args.rate}"
                    ),
                )
            )
        elif args.worker_action == "rate-approve":
            _json(
                client.request(
                    "POST",
                    f"/api/v1/rates/{args.rate_id}/approve",
                    json_body={},
                    idempotency_key=f"rate-approve:{args.rate_id}",
                )
            )
    finally:
        client.close()


def _workflow_command(args: argparse.Namespace) -> None:
    registry = WorkflowRegistry()
    if args.workflow_action == "install":
        result = registry.install(
            args.source,
            allow_unsigned=args.allow_unsigned,
            expected_publisher_key=args.publisher_key,
        )
        _json(
            {
                "id": result.manifest.id,
                "version": result.manifest.version,
                "digest": f"sha256:{result.digest}",
                "signed": result.signed,
                "path": str(result.path),
            }
        )
    elif args.workflow_action == "custom":
        source = Path(args.source).expanduser().resolve()
        manifest, _, _ = validate_package(source, allow_unsigned=True)
        if manifest.provenance != "custom":
            raise RegistryError("custom install requires manifest provenance: custom")
        result = registry.install(source, allow_unsigned=args.allow_unsigned)
        _json(
            {
                "id": result.manifest.id,
                "version": result.manifest.version,
                "digest": f"sha256:{result.digest}",
                "signed": result.signed,
                "provenance": "custom",
                "path": str(result.path),
            }
        )
    elif args.workflow_action == "list":
        _json(
            [
                {
                    "id": item.manifest.id,
                    "version": item.manifest.version,
                    "digest": f"sha256:{item.digest}",
                    "signed": item.signed,
                    "provenance": item.manifest.provenance,
                    "path": str(item.path),
                }
                for item in registry.installed()
            ]
        )
    elif args.workflow_action in {"show", "verify"}:
        source = Path(args.source).expanduser().resolve()
        manifest, digest, signed = validate_package(source, allow_unsigned=True)
        _json(
            {
                "manifest": manifest.model_dump(mode="json"),
                "digest": f"sha256:{digest}",
                "signed": signed,
            }
        )
    elif args.workflow_action == "search":
        _json(registry.search_index(args.index, args.query))
    elif args.workflow_action == "remove":
        registry.remove(args.workflow_id, args.version, provenance=args.provenance)
        _json({"removed": f"{args.workflow_id}@{args.version}"})
    elif args.workflow_action == "sign":
        key = Ed25519PrivateKey.from_private_bytes(
            b64url_decode(
                Path(args.key_file).read_text(encoding="ascii").strip(), expected_length=32
            )
        )
        digest = sign_package(Path(args.source).resolve(), key)
        _json({"digest": f"sha256:{digest}", "signed": True})
    elif args.workflow_action == "package":
        output = build_archive(Path(args.source).resolve(), Path(args.output).resolve())
        _json({"archive": str(output)})
    elif args.workflow_action == "publish":
        output = build_archive(Path(args.source).resolve(), Path(args.output).resolve())
        manifest, digest, signed = validate_package(Path(args.source).resolve())
        _json(
            {
                "id": manifest.id,
                "version": manifest.version,
                "digest": f"sha256:{digest}",
                "signed": signed,
                "archive": str(output),
            }
        )
    elif args.workflow_action == "update":
        installed = [
            item
            for item in registry.installed()
            if item.manifest.id == args.workflow_id and item.manifest.provenance == "market"
        ]
        if not installed:
            raise RegistryError("market workflow is not installed")
        current = max(Version(item.manifest.version) for item in installed)
        candidates = [
            entry
            for entry in registry.search_index(args.index, args.workflow_id)
            if entry.get("id") == args.workflow_id
            and entry.get("source")
            and Version(str(entry.get("version"))) > current
        ]
        if not candidates:
            _json({"id": args.workflow_id, "updated": False, "version": str(current)})
            return
        selected = max(candidates, key=lambda entry: Version(str(entry["version"])))
        publisher_keys = {item.manifest.publisher.public_key for item in installed}
        if len(publisher_keys) != 1 or None in publisher_keys:
            raise RegistryError("installed market releases have no single trusted publisher key")
        result = registry.install(
            str(selected["source"]),
            expected_digest=str(selected.get("digest") or "") or None,
            expected_publisher_key=next(iter(publisher_keys)),
        )
        _json(
            {
                "id": result.manifest.id,
                "updated": True,
                "version": result.manifest.version,
                "digest": f"sha256:{result.digest}",
            }
        )


def _resolve_workflow(reference: str) -> tuple[WorkflowManifest, Path, str]:
    workflow_id, separator, version = reference.partition("@")
    matches = [
        item
        for item in WorkflowRegistry().installed()
        if item.manifest.id == workflow_id and (not separator or item.manifest.version == version)
    ]
    if not matches:
        raise RegistryError(f"workflow is not installed: {reference}")
    selected = max(matches, key=lambda item: Version(item.manifest.version))
    return selected.manifest, selected.path, selected.digest


def _effective_parameters(manifest: WorkflowManifest, args: argparse.Namespace) -> dict[str, Any]:
    schema = manifest.parameters
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    parameters = {
        name: definition["default"]
        for name, definition in properties.items()
        if isinstance(definition, dict) and "default" in definition
    }
    parameters["prompt"] = args.prompt
    for item in args.parameter:
        name, separator, raw = item.partition("=")
        if not separator or not name:
            raise ValueError(f"parameter must use name=value: {item}")
        try:
            parameters[name] = json.loads(raw)
        except json.JSONDecodeError:
            parameters[name] = raw
    if args.image:
        parameters["image"] = Path(args.image).name
    if args.last_image:
        if not args.image:
            raise ValueError("--last-image requires --image")
        parameters["last_image"] = Path(args.last_image).name
    unknown = sorted(set(parameters) - set(properties))
    if unknown:
        raise ValueError(f"workflow does not define parameters: {unknown}")
    errors = sorted(
        Draft202012Validator(schema).iter_errors(parameters),
        key=lambda error: tuple(str(item) for item in error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "parameters"
        raise ValueError(f"workflow parameter validation failed at {location} ({error.validator})")
    return parameters


def _local_task_inputs(args: argparse.Namespace) -> list[LocalTaskInput]:
    values: list[LocalTaskInput] = []
    if args.image:
        values.append(LocalTaskInput.from_path("image", args.image))
    if args.last_image:
        values.append(LocalTaskInput.from_path("last_image", args.last_image))
    return values


def _workflow_public_requirements(
    variant: WorkflowVariant,
    *,
    operation: str,
) -> dict[str, Any]:
    """Build the exact public-only requirement set shared by preflight and submit."""

    return {
        "operation": operation,
        "payload_format": variant.payload_format,
        **(
            {"executor_min_version": variant.executor_min_version}
            if variant.executor_min_version is not None
            else {}
        ),
        **(
            {"runtime_min_version": variant.runtime_min_version}
            if variant.runtime_min_version is not None
            else {}
        ),
        **(
            {"min_vram_bytes": variant.min_vram_bytes}
            if variant.min_vram_bytes is not None
            else {}
        ),
        **(
            {"min_ram_bytes": variant.min_ram_bytes}
            if variant.min_ram_bytes is not None
            else {}
        ),
        "model_digests": [
            model.sha256
            if model.sha256.startswith("sha256:")
            else f"sha256:{model.sha256}"
            for model in variant.models
        ],
    }


_PREFLIGHT_MESSAGES = {
    "ready": (
        "当前有匹配的 Worker 和已审批费率，可以提交任务。",
        'vgen task submit "描述你想生成的视频" --wait',
    ),
    "queue_available": (
        "匹配的 Worker 正忙；仍可提交，任务会进入执行队列。",
        'vgen task submit "描述你想生成的视频" --wait',
    ),
    "queue_full": (
        "匹配 Worker 的等待队列已满。",
        "请等待已有任务完成后重新预检。",
    ),
    "no_allocated_worker": (
        "这个资源池还没有已授权的 Worker。",
        "请 Workspace 管理员先邀请或分配 Worker 到该资源池。",
    ),
    "worker_offline_or_busy": (
        "资源池里的 Worker 当前离线、维护中或已满载。",
        "请确认 Worker 正在运行，或稍后重新预检。",
    ),
    "capability_mismatch": (
        "在线 Worker 的执行器、模型、版本、内存或显存不满足这个工作流。",
        "请在 Worker 安装所需模型/执行器，完成心跳上报后重新预检。",
    ),
    "rate_not_approved": (
        "已有匹配 Worker，但它在这个 Workspace 的费率尚未审批。",
        "请 Workspace 管理员审批该 Worker 的费率后重新预检。",
    ),
}


def _comfy_input_bindings(
    mapping: dict[str, Any], uploaded: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for item in uploaded:
        name = item["input"]
        rule = mapping.get(name)
        if not isinstance(rule, dict):
            raise ValueError(f"workflow has no input mapping for {name}")
        fields = rule.get("input")
        fields = [fields] if isinstance(fields, str) else list(fields or [])
        if not fields:
            raise ValueError(f"workflow input mapping has no field for {name}")
        binding = {"input": name, "field": str(fields[0])}
        if rule.get("node") is not None:
            binding["node_id"] = str(rule["node"])
        elif rule.get("title") is not None:
            binding["node_title"] = str(rule["title"])
        else:
            raise ValueError(f"workflow input mapping has no node selector for {name}")
        bindings.append(binding)
    return bindings


def _task_reader_context(
    client: GatewayClient, task_id: str
) -> tuple[dict[str, Any], bytes, str, int]:
    reader = client.request("GET", f"/api/v1/tasks/{task_id}/reader-envelope")
    workspace_id = str(reader["workspace_id"])
    content_attempt_id = str(reader.get("content_attempt_id") or reader.get("attempt_id") or "")
    if not content_attempt_id:
        raise ValueError("Gateway reader envelope has no content_attempt_id")
    key_version = int(reader.get("key_version", 1))
    raw_envelope = reader.get("reader_envelope")
    if not isinstance(raw_envelope, str) or not raw_envelope:
        raise ValueError("task has no Workspace reader envelope")
    try:
        envelope = PayloadCiphertext.from_dict(json.loads(raw_envelope))
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("task Workspace reader envelope is invalid") from exc
    aad = task_aad(
        workspace_id=workspace_id,
        task_id=task_id,
        attempt_id=content_attempt_id,
        key_version=key_version,
    )
    task_data_key = unwrap_task_key_for_workspace(
        WorkspaceKeyStore().load(workspace_id, key_version),
        envelope,
        aad=aad,
    )
    return reader, task_data_key, content_attempt_id, key_version


def _verify_prepared_worker_certificate(worker: Mapping[str, Any]) -> None:
    raw_certificate = worker.get("certificate")
    raw_root_key = worker.get("owner_root_signing_public_key")
    try:
        certificate = (
            json.loads(raw_certificate) if isinstance(raw_certificate, str) else raw_certificate
        )
        root_key = b64url_decode(str(raw_root_key), expected_length=32)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValueError("Gateway returned an invalid Worker owner certificate") from exc
    if not isinstance(certificate, dict) or not verify_key_manifest(certificate, root_key):
        raise ValueError("Worker owner certificate signature is invalid")
    manifest = certificate.get("manifest")
    expected = {
        "kind": "vgen-worker-owner-certificate",
        "owner_root_key_id": certificate.get("signer_key_id"),
        "worker_key_id": device_key_id(
            b64url_decode(str(worker.get("signing_public_key")), expected_length=32)
        ),
        "worker_signing_public_key": worker.get("signing_public_key"),
        "worker_encryption_public_key": worker.get("encryption_public_key"),
    }
    if not isinstance(manifest, dict) or any(
        manifest.get(key) != value for key, value in expected.items()
    ):
        raise ValueError("Worker owner certificate does not bind the selected Worker keys")


def _verify_prepared_allocation(
    prepared: Mapping[str, Any],
    *,
    workspace_id: str,
    pool_id: str,
    worker: Mapping[str, Any],
    authority_store: WorkspaceAuthorityStore | None = None,
) -> None:
    """Verify Workspace authorization before disclosing a Task Data Key."""

    allocation = prepared.get("allocation")
    if not isinstance(allocation, Mapping):
        raise ValueError("Gateway returned no Workspace allocation proof")
    proof = allocation.get("proof")
    if not isinstance(proof, Mapping):
        raise ValueError("Gateway returned an invalid Workspace allocation proof")
    try:
        admin_user_id = str(allocation["admin_user_id"])
        root_public_text = str(allocation["admin_root_signing_public_key"])
        root_key = b64url_decode(root_public_text, expected_length=32)
        proof_payload = proof["payload"]
        (authority_store or WorkspaceAuthorityStore()).require(
            workspace_id=workspace_id,
            user_id=admin_user_id,
            presented_root_signing_public_key=root_public_text,
            presented_root_key_id=str(proof_payload["approver_root_key_id"]),
        )
        expected = build_allocation_proof_payload(
            allocation_id=str(allocation["id"]),
            workspace_id=workspace_id,
            pool_id=pool_id,
            worker_id=str(worker["id"]),
            worker_signing_public_key=str(worker["signing_public_key"]),
            worker_encryption_public_key=str(worker["encryption_public_key"]),
            worker_certificate=worker["certificate"],
            owner_consent_at=float(allocation["owner_consent_at"]),
            approver_root_key_id=str(proof_payload["approver_root_key_id"]),
            issued_at=int(proof_payload["issued_at"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Gateway returned a malformed Workspace allocation proof") from exc
    if not verify_allocation_proof(proof, root_key, expected=expected):
        raise ValueError(
            "Workspace allocation proof does not authorize the selected Worker and Pool"
        )


def _resolve_pool_id(
    client: GatewayClient,
    *,
    workspace_id: str,
    requested: str | None,
) -> str:
    from .worker_bundle import WorkerBundleError, select_pool

    pools = client.request("GET", f"/api/v1/workspaces/{workspace_id}/pools")
    if not isinstance(pools, list):
        raise WorkerBundleError("Gateway returned an invalid Pool list.")
    selected = select_pool(
        pools,
        requested=requested,
        default=getattr(client.profile, "default_pool", None),
    )
    return str(selected["id"])


def _download_task_outputs(
    client: GatewayClient,
    task_id: str,
    *,
    output_dir: str | Path,
    overwrite: bool,
) -> dict[str, Any]:
    task = client.get_task(task_id)
    reader, task_data_key, content_attempt_id, key_version = _task_reader_context(client, task_id)
    workspace_id = str(reader["workspace_id"])
    outputs = [
        artifact
        for artifact in task.get("artifacts", [])
        if artifact.get("direction") == "output"
        and artifact.get("state") == "available"
        and artifact.get("download_ticket")
    ]
    if not outputs:
        raise ValueError("task has no downloadable output artifacts")
    destination_root = Path(output_dir).expanduser().resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    downloaded: list[dict[str, Any]] = []
    used_names: set[str] = set()
    for index, artifact in enumerate(outputs):
        metadata = artifact.get("media_metadata")
        raw_name = metadata.get("filename") if isinstance(metadata, dict) else None
        filename = Path(str(raw_name or f"{artifact['id']}.bin")).name
        if not filename or filename in {".", ".."}:
            filename = f"output-{index:02d}.bin"
        media_type = (
            str(metadata.get("media_type"))
            if isinstance(metadata, dict) and metadata.get("media_type")
            else None
        )
        filename = with_safe_media_extension(filename, media_type)
        if filename in used_names:
            filename = f"{index:02d}-{filename}"
        used_names.add(filename)
        destination = destination_root / filename
        staged = destination_root / f".vgen-output-{uuid.uuid4().hex}.part"
        try:
            receipt = download_and_decrypt_output(
                artifact,
                staged,
                task_data_key=task_data_key,
                workspace_id=workspace_id,
                task_id=task_id,
                artifact_attempt_id=str(artifact.get("attempt_id") or content_attempt_id),
                key_version=key_version,
            )
            destination = _publish_task_output(staged, destination, overwrite=overwrite)
        finally:
            staged.unlink(missing_ok=True)
        downloaded.append(
            {
                "artifact_id": artifact["id"],
                "path": str(destination),
                "size": receipt.size_bytes,
            }
        )
    return {"task_id": task_id, "outputs": downloaded}


def _file_content_fingerprint(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def _publish_task_output(staged: Path, requested: Path, *, overwrite: bool) -> Path:
    """Publish a decrypted output without turning a safe name collision into task failure."""

    if overwrite:
        os.replace(staged, requested)
        return requested

    staged_fingerprint: tuple[int, str] | None = None
    for sequence in range(10_000):
        candidate = (
            requested
            if sequence == 0
            else requested.with_name(
                f"{requested.stem}-{sequence:02d}{requested.suffix}"
            )
        )
        try:
            os.link(staged, candidate)
            return candidate
        except FileExistsError:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if staged_fingerprint is None:
                staged_fingerprint = _file_content_fingerprint(staged)
            if _file_content_fingerprint(candidate) == staged_fingerprint:
                return candidate
    raise ValueError(f"could not allocate a unique output filename below: {requested.parent}")


def _wait_for_task(
    client: GatewayClient,
    task_id: str,
    *,
    interval: float,
    timeout: float,
) -> dict[str, Any]:
    if interval <= 0 or timeout <= 0:
        raise ValueError("task wait interval and timeout must be positive")
    deadline = time.monotonic() + timeout
    display: dict[str, Any] = {
        "state": None,
        "attempt_id": None,
        "stage": None,
        "percent": -1,
    }
    while True:
        task = client.get_task(task_id)
        _print_task_update(task, display)
        state = str(task.get("state") or "unknown")
        if state in {"succeeded", "failed", "cancelled", "expired"}:
            return task
        if time.monotonic() >= deadline:
            raise TimeoutError("task wait timed out")
        time.sleep(interval)


def _task_progress(task: Mapping[str, Any]) -> tuple[str, str, int] | None:
    attempts = task.get("attempts")
    if not isinstance(attempts, list):
        return None
    for index in range(len(attempts) - 1, -1, -1):
        attempt = attempts[index]
        if not isinstance(attempt, Mapping):
            continue
        progress = attempt.get("progress")
        if isinstance(progress, str):
            try:
                progress = json.loads(progress)
            except json.JSONDecodeError:
                continue
        if not isinstance(progress, Mapping):
            continue
        fraction = progress.get("fraction")
        stage = progress.get("stage")
        if (
            not isinstance(fraction, (int, float))
            or isinstance(fraction, bool)
            or not 0 <= float(fraction) <= 1
            or not isinstance(stage, str)
            or not stage
        ):
            continue
        attempt_id = str(attempt.get("id") or f"attempt-{index}")
        return attempt_id, stage, min(100, max(0, round(float(fraction) * 100)))
    return None


def _task_progress_label(stage: str) -> str:
    if stage in {"preparing", "downloading_inputs"}:
        return "准备输入"
    if stage in {"queued", "sampling", "sampled"}:
        return "生成采样"
    if stage.startswith("node:"):
        return "生成处理"
    if stage == "uploading_outputs":
        return "上传结果"
    return "任务处理"


def _print_task_update(task: Mapping[str, Any], display: dict[str, Any]) -> None:
    state = str(task.get("state") or "unknown")
    if state != display["state"]:
        print(f"任务状态：{state}", file=sys.stderr)
        display["state"] = state

    progress = _task_progress(task)
    if progress is None:
        return
    attempt_id, stage, percent = progress
    if attempt_id != display["attempt_id"]:
        display["attempt_id"] = attempt_id
        display["stage"] = None
        display["percent"] = -1
    previous_percent = int(display["percent"])
    if percent < previous_percent:
        return
    stage_changed = stage != display["stage"]
    if not stage_changed and percent < previous_percent + 2 and percent != 100:
        return
    if stage.startswith("node:"):
        print("生成处理中：当前节点暂无细分进度", file=sys.stderr)
    else:
        print(f"{_task_progress_label(stage)}：{percent}%", file=sys.stderr)
    display["stage"] = stage
    display["percent"] = percent


def _task_command(args: argparse.Namespace) -> None:
    client = _client(args.profile)
    try:
        if args.task_action == "preflight":
            manifest, directory, digest = _resolve_workflow(args.workflow)
            parameters = _effective_parameters(manifest, args)
            variant = next(
                (item for item in manifest.variants if item.executor_type == args.executor), None
            )
            if variant is None:
                raise ValueError(f"workflow has no {args.executor} executor variant")
            template = load_json(directory / variant.payload)
            mapping = json.loads((directory / str(variant.mapping)).read_text(encoding="utf-8"))
            _, _, operation = build_comfy_graph(template, mapping, parameters)
            workspace_id = args.workspace or client.profile.default_workspace
            if not workspace_id:
                raise ValueError("task preflight requires a default Workspace or --workspace")
            pool_id = _resolve_pool_id(client, workspace_id=workspace_id, requested=args.pool)
            checked = client.preflight_task(
                {
                    "workspace_id": workspace_id,
                    "pool_id": pool_id,
                    "workflow_ref": f"{manifest.id}@{manifest.version}",
                    "workflow_digest": f"sha256:{digest}",
                    "executor_type": variant.executor_type,
                    "public_requirements": _workflow_public_requirements(
                        variant,
                        operation=operation,
                    ),
                }
            )
            message, next_step = _PREFLIGHT_MESSAGES.get(
                str(checked.get("state")),
                ("Gateway 返回了未知预检状态。", "请升级 CLI 后重试。"),
            )
            _json({**checked, "message": message, "next": next_step})
        elif args.task_action == "submit":
            manifest, directory, digest = _resolve_workflow(args.workflow)
            parameters = _effective_parameters(manifest, args)
            local_inputs = _local_task_inputs(args)
            variant = next(
                (item for item in manifest.variants if item.executor_type == args.executor), None
            )
            if variant is None:
                raise ValueError(f"workflow has no {args.executor} executor variant")
            template = load_json(directory / variant.payload)
            mapping = json.loads((directory / str(variant.mapping)).read_text(encoding="utf-8"))
            graph, effective, operation = build_comfy_graph(template, mapping, parameters)
            workspace_id = args.workspace or client.profile.default_workspace
            if not workspace_id:
                raise ValueError("task submit requires a default Workspace or --workspace")
            pool_id = _resolve_pool_id(client, workspace_id=workspace_id, requested=args.pool)
            prepared = client.prepare_task(
                {
                    "workspace_id": workspace_id,
                    "pool_id": pool_id,
                    "workflow_ref": f"{manifest.id}@{manifest.version}",
                    "workflow_digest": f"sha256:{digest}",
                    "executor_type": variant.executor_type,
                    "public_requirements": _workflow_public_requirements(
                        variant,
                        operation=operation,
                    ),
                    "client_channel": "cli",
                    "priority": args.priority,
                    "input_artifacts": [item.prepare_descriptor() for item in local_inputs],
                },
                idempotency_key=args.idempotency_key or f"submit:{uuid.uuid4()}",
            )
            attempt_id = prepared.get("attempt_id")
            if not attempt_id:
                raise RuntimeError("Gateway prepare response has no attempt_id required by E2EE")
            worker = prepared["worker"]
            _verify_prepared_worker_certificate(worker)
            _verify_prepared_allocation(
                prepared,
                workspace_id=workspace_id,
                pool_id=pool_id,
                worker=worker,
            )
            key_version = int(prepared.get("key_version", 1))
            content_attempt_id = str(prepared.get("content_attempt_id") or attempt_id)
            content_aad = task_aad(
                workspace_id=workspace_id,
                task_id=prepared["id"],
                attempt_id=content_attempt_id,
                key_version=key_version,
            )
            task_data_key = generate_task_data_key()
            uploaded = encrypt_and_upload_inputs(
                local_inputs,
                list(prepared.get("artifact_tickets") or []),
                task_data_key=task_data_key,
                workspace_id=workspace_id,
                task_id=prepared["id"],
                content_attempt_id=content_attempt_id,
                key_version=key_version,
            )
            opaque = json.dumps(
                {
                    "workflow": graph,
                    "input_bindings": _comfy_input_bindings(mapping, uploaded),
                    "effective_parameters": effective,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            encrypted_payload = encrypt_payload(task_data_key, opaque, aad=content_aad)
            worker_envelope = wrap_task_key(
                b64url_decode(worker["encryption_public_key"], expected_length=32),
                task_data_key,
                aad=task_aad(
                    workspace_id=workspace_id,
                    task_id=prepared["id"],
                    attempt_id=attempt_id,
                    key_version=key_version,
                ),
            )
            reader_envelope = wrap_task_key_for_workspace(
                WorkspaceKeyStore().load(workspace_id, key_version),
                task_data_key,
                aad=content_aad,
            )
            committed = client.commit_task(
                prepared["id"],
                {
                    "encrypted_payload": json.dumps(
                        encrypted_payload.to_dict(), separators=(",", ":")
                    ),
                    "worker_tdk_envelope": json.dumps(
                        worker_envelope.to_dict(), separators=(",", ":")
                    ),
                    "reader_envelope": json.dumps(reader_envelope.to_dict(), separators=(",", ":")),
                    "key_algorithm": HPKE_ALGORITHM,
                    "artifacts": [],
                    "artifact_receipts": [
                        {
                            "artifact_id": item["artifact_id"],
                            "encrypted_size": item["encrypted_size"],
                            "content_digest": item["content_digest"],
                        }
                        for item in uploaded
                    ],
                },
            )
            if not args.wait:
                _json(committed)
            else:
                task_id = str(committed.get("id") or prepared["id"])
                completed = _wait_for_task(
                    client,
                    task_id,
                    interval=args.wait_interval,
                    timeout=args.timeout,
                )
                if completed.get("state") != "succeeded":
                    raise ValueError(f"task ended without a video (state={completed.get('state')})")
                _json(
                    _download_task_outputs(
                        client,
                        task_id,
                        output_dir=args.output_dir,
                        overwrite=args.overwrite,
                    )
                )
        elif args.task_action == "show":
            _json(client.get_task(args.task_id))
        elif args.task_action == "get":
            _json(
                _download_task_outputs(
                    client,
                    args.task_id,
                    output_dir=args.output_dir,
                    overwrite=args.overwrite,
                )
            )
        elif args.task_action == "list":
            workspace_id = args.workspace or client.profile.default_workspace
            if not workspace_id:
                raise ValueError("task list requires a default Workspace or --workspace")
            page = client.list_task_page(
                workspace_id=workspace_id,
                limit=args.limit,
                cursor=args.cursor,
                state=args.state,
                sort=args.sort,
                order=args.order,
            )
            _normalize_task_list_sort(page, sort=args.sort, order=args.order)
            page["items"] = [
                {
                    **item,
                    "show_command": shlex.join(
                        ["vgen", "task", "show", str(item["id"])]
                        + (["--profile", args.profile] if args.profile else [])
                    ),
                }
                for item in page.get("items", [])
            ]
            next_args = [
                "vgen",
                "task",
                "list",
                "--cursor",
                str(page["next_cursor"]),
                "--limit",
                str(args.limit),
                "--sort",
                args.sort,
                "--order",
                args.order,
            ]
            if args.workspace:
                next_args.extend(("--workspace", args.workspace))
            if args.state:
                next_args.extend(("--state", args.state))
            if args.profile:
                next_args.extend(("--profile", args.profile))
            if args.format == "json":
                next_args.append("--format=json")
            page["next"] = shlex.join(next_args) if page.get("next_cursor") else None
            if args.format == "json":
                _json(page)
            else:
                _print_task_list(page)
        elif args.task_action == "cancel":
            _json(client.close_task(args.task_id))
        elif args.task_action == "retry":
            retry = client.request(
                "POST",
                f"/api/v1/tasks/{args.task_id}/retry",
                json_body={},
                idempotency_key=f"retry:{args.task_id}:{uuid.uuid4()}",
            )
            reader, task_data_key, _, key_version = _task_reader_context(client, args.task_id)
            worker = retry["worker"]
            _verify_prepared_worker_certificate(worker)
            _verify_prepared_allocation(
                retry,
                workspace_id=str(retry["workspace_id"]),
                pool_id=str(retry["pool_id"]),
                worker=worker,
            )
            attempt_id = str(retry["attempt_id"])
            worker_envelope = wrap_task_key(
                b64url_decode(worker["encryption_public_key"], expected_length=32),
                task_data_key,
                aad=task_aad(
                    workspace_id=str(reader["workspace_id"]),
                    task_id=args.task_id,
                    attempt_id=attempt_id,
                    key_version=key_version,
                ),
            )
            _json(
                client.request(
                    "POST",
                    f"/api/v1/tasks/{args.task_id}/rekey",
                    json_body={
                        "replacement_worker_id": worker["id"],
                        "worker_tdk_envelope": json.dumps(
                            worker_envelope.to_dict(), separators=(",", ":")
                        ),
                        "key_algorithm": HPKE_ALGORITHM,
                    },
                    idempotency_key=f"rekey:{args.task_id}:{attempt_id}",
                )
            )
        elif args.task_action == "watch":
            _json(
                _wait_for_task(
                    client,
                    args.task_id,
                    interval=args.interval,
                    timeout=args.timeout,
                )
            )
        elif args.task_action == "usage":
            workspace_id = args.workspace or client.profile.default_workspace
            if not workspace_id:
                raise ValueError("workspace is required")
            _json(client.request("GET", f"/api/v1/workspaces/{workspace_id}/usage"))
    finally:
        client.close()


def _usage_command(args: argparse.Namespace) -> None:
    client = _client(args.profile)
    try:
        workspace_id = args.workspace or client.profile.default_workspace
        if not workspace_id:
            raise ValueError("workspace is required")
        values = client.request(
            "GET",
            f"/api/v1/workspaces/{workspace_id}/usage",
            params={"limit": args.limit},
        )
        if args.usage_action == "list":
            _json(values)
            return
        selected = next(
            (
                item
                for item in values
                if item.get("id") == args.entry_id
                or item.get("attempt_id") == args.entry_id
                or item.get("task_id") == args.entry_id
            ),
            None,
        )
        if selected is None:
            raise ValueError("usage entry is not present in the requested Workspace window")
        _json(selected)
    finally:
        client.close()


_COMMAND_HELP: dict[tuple[str, ...], str] = {
    ("setup",): "在 Mac 上完成首次初始化，创建身份、Workspace、资源池和 Home Broker。",
    ("upgrade",): "检查并升级已托管安装的 VGen CLI，同时刷新 Home Broker。",
    ("identity",): "管理用户身份、设备登录、恢复和撤销。",
    ("identity", "init"): "创建新的本地用户身份和恢复材料。",
    ("identity", "recover"): "使用恢复词或私钥文件在当前设备恢复用户身份。",
    ("identity", "show"): "查看本地身份的公开信息，不显示私钥。",
    ("identity", "device"): "查看当前身份对应的本地设备信息。",
    ("identity", "revoke"): "撤销指定设备，或仅忘记当前设备的本地身份。",
    ("identity", "login"): "向 Gateway 发起密钥挑战并建立短期登录会话。",
    ("identity", "logout"): "删除当前 Profile 保存的本地登录会话。",
    ("identity", "enroll"): "使用一次性邀请加入 Gateway 并创建用户身份。",
    ("identity", "device-enroll"): "使用设备邀请把当前设备接入已有用户身份。",
    ("profile",): "管理 Gateway 地址、默认 Workspace 和本地身份的连接配置。",
    ("profile", "add"): "保存一个 Gateway 连接配置，并可设为当前默认配置。",
    ("profile", "endpoint-set"): "验证新 Gateway 后安全更新地址，保留身份和 Workspace 绑定。",
    ("profile", "use"): "切换后续命令默认使用的 Profile。",
    ("profile", "show"): "查看指定或当前 Profile 的连接配置。",
    ("profile", "list"): "列出本机保存的全部 Profile。",
    ("gateway",): "执行 Gateway 首次绑定和健康检查。",
    ("gateway", "bootstrap"): "用一次性 Bootstrap code 绑定首位 Gateway Operator。",
    ("gateway", "health"): "查看 Gateway、数据库以及 Worker 在线统计。",
    ("service",): "管理供 API 程序使用的独立 Service 身份和密钥。",
    ("service", "enroll"): "使用邀请创建 Service 密钥并接入 Workspace。",
    ("service", "use"): "把 Profile 绑定到本地已有的 Service 凭据。",
    ("service", "login"): "为当前 Service 建立短期登录会话。",
    ("service", "logout"): "删除当前 Service 的本地登录会话。",
    ("service", "show"): "查看当前 Profile 绑定的 Service 信息。",
    ("service", "revoke-local"): "从本机删除 Service 凭据和会话，不撤销服务端主体。",
    ("service", "key-sync"): "同步 Service 可访问的 Workspace 数据密钥。",
    ("workspace",): "管理 Workspace、资源池、成员准入、密钥和审计记录。",
    ("workspace", "create"): "创建 Workspace，并初始化本地端到端加密密钥。",
    ("workspace", "list"): "列出当前用户可访问的 Workspace。",
    ("workspace", "pool-create"): "在 Workspace 中创建 Worker 资源池。",
    ("workspace", "pool-list"): "列出 Workspace 中的资源池。",
    ("workspace", "owner-migrate"): "确认并固定旧版 Workspace Owner 公钥。",
    ("workspace", "key-sync"): "同步当前设备可访问的 Workspace 数据密钥。",
    ("workspace", "key-grant"): "把指定版本的 Workspace 密钥安全封装给接收方。",
    ("workspace", "key-grant-enrollment"): "向已完成准入的用户授予 Workspace 密钥。",
    ("workspace", "key-rotate"): "轮换 Workspace 数据密钥并生成新版本。",
    ("workspace", "authority-pin"): "在本地固定可信 Workspace 管理员公钥。",
    ("workspace", "invite"): "生成用户、设备或 Service 的一次性邀请。",
    ("workspace", "apply"): "主动申请加入指定 Workspace。",
    ("workspace", "decide"): "批准或拒绝一条待处理的准入申请。",
    ("workspace", "enrollment-list"): "列出 Workspace 的邀请领取和申请记录。",
    ("workspace", "allocation-list"): "列出 Workspace 中的 Worker 资源分配。",
    ("workspace", "audit"): "查看 Workspace 控制面审计记录。",
    ("join",): "通过邀请加入他人的 Workspace，并在需要时等待管理员批准。",
    ("broker",): "管理 Home Broker、Broker Device 和 Worker 维护任务。",
    ("broker", "create"): "创建属于当前用户的 Logical Home Broker。",
    ("broker", "list"): "列出当前用户拥有的 Broker。",
    ("broker", "status"): "查看 Gateway 记录的 Broker Device 和心跳状态。",
    ("broker", "local-status"): "检查这台 Mac 上 Home Broker 的进程和运行版本。",
    ("broker", "service-refresh"): "让本机 Home Broker 切换到当前 CLI 版本并重新加载。",
    ("broker", "device"): "把一个已登记设备关联到指定 Broker。",
    ("broker", "serve"): "前台运行 Home Broker 轮询服务，适合调试。",
    ("broker", "worker-update"): "向 Worker 推送经过校验的 VGen wheel 更新任务。",
    ("broker", "model-install"): "要求 Worker 按工作流清单校验并下载缺失模型。",
    ("broker", "maintenance-list"): "列出 Worker 更新和模型安装任务。",
    ("broker", "maintenance-show"): "查看一条 Worker 维护任务的状态和结果。",
    ("broker", "maintenance-cancel"): "取消尚未结束的 Worker 维护任务。",
    ("worker",): "用统一安装流程接入、查看、退出和运行 GPU Worker。",
    ("worker", "add"): "创建一次性邀请，等待 Windows 验证并批准 Worker 接入。",
    ("worker", "list"): "列出 Worker、状态、心跳和能力信息。",
    ("worker", "manager-set"): "指定负责维护某台 Worker 的 Broker。",
    ("worker", "offer"): "由 Worker 所有者提议把 Worker 加入资源池。",
    ("worker", "approve-allocation"): "由 Workspace 管理员批准 Worker 资源分配。",
    ("worker", "leave"): "让 Worker 停止接收新任务并退出资源池。",
    ("worker", "revoke"): "立即撤销并隔离一台 Worker。",
    ("worker", "rate-propose"): "提交 Worker 的计算和流量计费建议。",
    ("worker", "rate-approve"): "批准一条 Worker 费率建议。",
    ("worker", "serve"): "运行 Worker 主循环，领取、执行并回传加密任务。",
    ("workflow",): "安装、校验、制作和管理工作流包。",
    ("workflow", "install"): "从本地文件或市场地址安装签名工作流包。",
    ("workflow", "custom"): "安装自定义工作流，并与市场版本隔离保存。",
    ("workflow", "list"): "列出本机已安装的工作流版本。",
    ("workflow", "show"): "查看工作流清单、参数和依赖。",
    ("workflow", "verify"): "校验工作流包的结构、摘要和签名。",
    ("workflow", "search"): "在指定市场索引中搜索工作流。",
    ("workflow", "remove"): "删除本机安装的指定工作流版本。",
    ("workflow", "sign"): "使用作者私钥签署工作流包。",
    ("workflow", "package"): "把工作流目录打包为可分发文件。",
    ("workflow", "publish"): "把工作流包发布到本地市场目录。",
    ("workflow", "update"): "从市场索引安装工作流的可用更新。",
    ("task",): "预检、提交、查看、取消和下载生成任务。",
    ("task", "preflight"): "只检查工作流、Worker 能力和费率，不创建任务。",
    ("task", "submit"): "加密提示词和输入文件，提交视频生成任务。",
    ("task", "show"): "查看任务状态、分配 Worker 和执行 Attempt。",
    ("task", "cancel"): "取消尚未结束的任务。",
    ("task", "retry"): "为失败或需要重封装的任务创建新 Attempt。",
    ("task", "get"): "下载并解密已完成任务的输出文件。",
    ("task", "list"): "以日志式短列表分页显示 Workspace 中的任务。",
    ("task", "watch"): "持续等待任务结束并显示最终状态。",
    ("task", "usage"): "查看任务 Attempt 的原始用量和计费记录。",
    ("usage",): "查询跨任务的 Worker 用量和 billing_token 账本。",
    ("usage", "list"): "列出 Workspace 的近期用量账本。",
    ("usage", "show"): "按账本、Attempt 或 Task ID 查找详细用量。",
}


_ARGUMENT_HELP: dict[str, str] = {
    "accept_legacy_tofu": "跳过交互确认并接受屏幕显示的旧版 Owner 公钥；仅限已人工核对时使用。",
    "accept_license": "接受模型要求的许可证标识；多个许可证可重复传入。",
    "alias": "本地身份别名，默认使用 default。",
    "allocation_id": "待批准的 Worker allocation ID。",
    "allow_http": "允许连接明文 HTTP Gateway；仅建议本机测试使用。",
    "allow_unsigned": "允许安装未签名工作流；仅限已人工审查的本地包。",
    "announce": "启动后立即向 Gateway 上报 Worker 能力。",
    "broker": "Broker ID；省略时使用当前 Profile 的 Home Broker。",
    "broker_device_id": "运行该 Broker 服务的 Broker Device ID。",
    "broker_id": "Logical Broker ID。",
    "broker_name": "首次创建的 Home Broker 名称。",
    "bootstrap_code_file": "从指定文件安全读取一次性 Bootstrap code。",
    "bootstrap_code_stdin": "从标准输入安全读取一次性 Bootstrap code。",
    "capacity": "Worker 可同时执行的任务数。",
    "check": "只检查是否存在新版本，不执行安装。",
    "code": "Worker 屏幕显示的短验证码，用于人工核对公钥。",
    "cursor": "上一页返回的不透明翻页游标。",
    "comfy_model_root": "ComfyUI 模型目录；用于模型校验和维护。",
    "comfy_output_dir": "ComfyUI 输出目录。",
    "comfy_policy_file": "本机管理员审核过的 ComfyUI 图白名单文件。",
    "comfy_url": "本机 ComfyUI API 地址，默认 http://127.0.0.1:8188。",
    "comfyui_root": "Windows 上包含 ComfyUI main.py 的目录；常见位置会自动识别。",
    "credentials_account": "在系统 Keychain 中保存或读取凭据所用的账户名。",
    "credentials_file": "凭据文件路径；应限制为仅当前用户可读。",
    "credentials_keyring": "从系统凭据存储读取 Worker 凭据。",
    "dangerously_export_recovery": "把恢复材料明文导出到指定文件；文件权限会限制为 0600。",
    "device_id": "设备 ID；省略时表示当前本地设备。",
    "device_name": "这台设备在 Gateway 中显示的名称。",
    "display_name": "用户在 Gateway 和 Workspace 中显示的名称。",
    "endpoint": "Gateway 的 HTTPS 地址，例如 https://vgen.example.com。",
    "enrollment_id": "待处理的 Enrollment ID。",
    "entry_id": "Usage Ledger、Attempt 或 Task ID。",
    "executor": "执行器类型，当前通常为 comfyui。",
    "executor_version": "Worker 对外声明的执行器版本。",
    "expected_key_version": "预期的当前密钥版本；不匹配时拒绝轮换以避免并发覆盖。",
    "force": "立即停止当前 Attempt 并退出，不等待任务自然结束。",
    "format": "输出格式：text 适合终端阅读，json 适合脚本处理。",
    "forget_local": "只删除本机设备密钥；不会向 Gateway 撤销远端设备。",
    "gateway_url": "Gateway 的完整 HTTPS 地址。",
    "generate_identity": "为 Worker 新生成独立密钥。",
    "idempotency_key": "幂等键；网络重试时复用同一值可避免重复创建或计费。",
    "identity": "本地用户身份别名，默认使用当前 Profile 配置。",
    "include_revoked": "同时显示已撤销的 Workspace 成员。",
    "identity_account": "Worker 身份在系统凭据存储中的账户名。",
    "identity_file": "Worker 私钥文件路径；应限制为仅当前用户可读。",
    "image": "首帧图片路径；不指定图片时执行文生视频。",
    "index": "工作流市场索引文件或 URL。",
    "interval": "轮询间隔秒数。",
    "invite_stdin": "从标准输入读取完整邀请 URI，避免 secret 进入命令历史。",
    "job_id": "Worker 维护任务 ID。",
    "json": "以便于脚本处理的 JSON 格式输出。",
    "key_file": "用于签署工作流包的 Ed25519 私钥文件。",
    "key_version": "Workspace 数据密钥版本；省略时使用最新版本。",
    "kind": "准入主体类型，例如 user、broker_device、service 或 workspace_member。",
    "last_image": "尾帧图片路径；与 --image 同时指定时生成首尾帧视频。",
    "lease_ttl": "Worker lease 有效秒数。",
    "limit": "最多返回的记录数。",
    "local_artifact_root": "允许 Worker 读取的本地 artifact 根目录；可重复指定。",
    "manager_broker": "负责该 Worker 更新和模型维护的 Broker ID。",
    "method": "邀请流程：direct_invite 领取即生效，invite_approval 领取后还需审批。",
    "name": "资源名称。",
    "no_broker_service": "完成初始化但不安装或启动本机 Home Broker 服务。",
    "no_home_broker": "只初始化用户和 Workspace，不创建 Home Broker。",
    "no_use": "保存 Profile 后不把它切换为当前默认配置。",
    "non_interactive": "禁用交互询问；缺少必要参数时直接报错。",
    "once": "只执行一轮轮询后退出，适合诊断。",
    "output": "输出文件或目录路径。",
    "output_dir": "保存下载结果的目录。",
    "overwrite": "允许覆盖本地已存在的目标文件或记录。",
    "parameter": "工作流参数，格式为 key=value；可重复指定。",
    "policy": "资源池公开调度策略的 JSON 对象。",
    "poll_seconds": "Broker 轮询 Gateway 的间隔秒数。",
    "pool": "Pool 名称或 ID；仅有一个资源池时通常可省略。",
    "pool_name": "首次创建的默认 GPU Pool 名称。",
    "priority": "任务调度优先级；数值越大优先级越高。",
    "private_key_file": "恢复私钥文件；省略时从隐藏输入读取恢复词。",
    "profile": "要使用的本地 Profile；省略时使用当前默认 Profile。",
    "prompt": "视频生成提示词；内容会在本地加密后提交。",
    "provenance": "限定删除 market 或 custom 来源的工作流。",
    "publisher_key": "通过独立可信渠道取得的作者 Ed25519 公钥。",
    "query": "工作流搜索关键词。",
    "rate_id": "待批准的 Rate Card ID。",
    "rate": "为后续按视频时长和生成耗时计费预留的每秒费率，单位为 microtoken。",
    "recipient_id": "密钥接收方的 User、Device 或 Service ID。",
    "recipient_type": "密钥接收方类型。",
    "recovery_file": "已有恢复文件路径；用于恢复而不是创建新用户。",
    "relationship": "加入 Workspace 后的关系或角色说明。",
    "resume": "继续此前因等待审批或密钥授权而暂停的接入流程。",
    "root_key_id": "用户根签名公钥的 key ID。",
    "root_signing_public_key": "经过独立核对的用户根 Ed25519 公钥。",
    "scope": "授予主体的权限 scope；可重复指定。",
    "service_id": "API Service ID。",
    "session_token_file": "保存短期 Worker session token 的文件。",
    "source": "工作流目录、包文件、已安装引用或下载地址。",
    "state": "按 Enrollment 状态筛选，例如 pending、active 或 rejected。",
    "subject_key_fingerprint": "将邀请绑定到指定主体公钥的 SHA-256 指纹。",
    "task_id": "任务 ID。",
    "timeout": "最长等待秒数，超时只停止本地等待。",
    "ttl": "邀请有效秒数。",
    "use": "完成后把新建资源设为当前 Profile 的默认值。",
    "user_id": "用户 ID。",
    "verification_code": "双方通过独立渠道核对的验证码。",
    "version": "工作流版本号。",
    "wait": "持续等待远端操作完成。",
    "wait_interval": "等待期间查询状态的间隔秒数。",
    "wheel": "经过审查、用于更新 Worker 的 VGen wheel 文件。",
    "work_root": "Worker 解密和执行任务所用的临时工作目录。",
    "worker": "Worker 名称或 ID；仅有一台自有 Worker 时可省略。",
    "worker_id": "Worker ID。",
    "workflow": "已安装工作流引用，格式通常为 namespace/name。",
    "workflow_id": "工作流 ID，格式为 namespace/name。",
    "workspace": "Workspace 名称或 ID；省略时使用 Profile 默认值。",
    "workspace_name": "首次创建的 Workspace 名称。",
    "yes": "不再询问确认，直接安装可用更新。",
}


_OPTION_HELP: dict[str, str] = {
    "--approve": "批准该准入申请。",
    "--reject": "拒绝该准入申请。",
    "--version": "显示当前 VGen CLI 版本并退出。",
}


_COMMAND_ARGUMENT_HELP: dict[tuple[str, ...], str] = {
    ("task", "list", "order"): "排序方向：desc 倒序，asc 正序。",
    ("task", "list", "sort"): (
        "排序因子：created 提交时间、updated 更新时间、priority 优先级、state 状态。"
    ),
    ("task", "list", "state"): (
        "按任务状态筛选，例如 queued、running、succeeded 或 failed。"
    ),
}


class _VGenHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def _get_help_string(self, action: argparse.Action) -> str:
        help_text = action.help or ""
        default = action.default
        if (
            action.option_strings
            and default not in (None, "", [], argparse.SUPPRESS)
            and not isinstance(default, bool)
            and "%(default)" not in help_text
        ):
            return f"{help_text}（默认：%(default)s）"
        return help_text


def _enhance_cli_help(parser: argparse.ArgumentParser) -> None:
    """Apply consistent, user-facing help without exposing hidden installer flags."""

    def visit(current: argparse.ArgumentParser, path: tuple[str, ...]) -> None:
        current.formatter_class = _VGenHelpFormatter
        current._optionals.title = "选项"
        subparser_actions = [
            action
            for action in current._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        current._positionals.title = "可用命令" if subparser_actions else "参数"
        if path in _COMMAND_HELP:
            current.description = _COMMAND_HELP[path]

        for action in current._actions:
            if action.dest == "help":
                action.help = "显示当前命令的帮助信息并退出。"
                continue
            if isinstance(action, argparse._SubParsersAction):
                action.metavar = "命令"
                existing_choices = {choice.dest: choice for choice in action._choices_actions}
                ordered_choices = []
                for name in action.choices:
                    if name not in existing_choices:
                        choice = action._ChoicesPseudoAction(
                            name,
                            (),
                            _COMMAND_HELP.get((*path, name)),
                        )
                        existing_choices[name] = choice
                    ordered_choices.append(existing_choices[name])
                action._choices_actions[:] = ordered_choices
                for choice in action._choices_actions:
                    child_path = (*path, choice.dest)
                    choice.help = _COMMAND_HELP.get(child_path, choice.help)
                for name, child in action.choices.items():
                    visit(child, (*path, name))
                continue
            if action.help == argparse.SUPPRESS:
                continue
            option_help = next(
                (_OPTION_HELP[option] for option in action.option_strings if option in _OPTION_HELP),
                None,
            )
            action.help = (
                option_help
                or _COMMAND_ARGUMENT_HELP.get((*path, action.dest))
                or _ARGUMENT_HELP.get(
                    action.dest,
                    f"设置 {action.dest.replace('_', '-')}。",
                )
            )

    parser.description = "VGen：通过 Gateway 安全共享 GPU Worker，并使用端到端加密提交生成任务。"
    parser.epilog = (
        "常用流程：\n"
        "  vgen setup --gateway https://vgen.example.com\n"
        "  vgen gateway health\n"
        "  vgen worker list\n"
        "  vgen task submit '一只猫在草地上奔跑' --wait\n\n"
        "查看某组命令：vgen <命令> --help；查看具体操作：vgen <命令> <子命令> --help。"
    )
    visit(parser, ())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vgen")
    parser.add_argument("--version", action="version", version=f"vgen {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser(
        "setup",
        help="initialize this Mac as a Home Broker without handling resource IDs",
    )
    setup.add_argument("--gateway", "--endpoint", dest="endpoint")
    setup.add_argument("--display-name")
    setup.add_argument("--workspace-name")
    setup.add_argument("--pool-name")
    setup.add_argument("--broker-name")
    setup.add_argument("--device-name")
    setup.add_argument("--profile", default="home")
    setup.add_argument("--identity", default="default")
    setup.add_argument("--recovery-file", type=Path)
    setup.add_argument("--workflow-package", type=Path, help=argparse.SUPPRESS)
    bootstrap_source = setup.add_mutually_exclusive_group()
    bootstrap_source.add_argument("--bootstrap-code-file", type=Path)
    bootstrap_source.add_argument("--bootstrap-code-stdin", action="store_true")
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--no-home-broker", action="store_true")
    setup.add_argument("--no-broker-service", action="store_true")
    setup.add_argument("--json", action="store_true")

    upgrade = sub.add_parser("upgrade", help="upgrade the managed macOS CLI and Home Broker")
    upgrade.add_argument("--profile")
    upgrade.add_argument("--check", action="store_true", help="only report whether an update exists")
    upgrade.add_argument("--yes", action="store_true", help="install without an interactive prompt")

    identity = sub.add_parser("identity")
    identity_sub = identity.add_subparsers(dest="identity_action", required=True)
    identity_init = identity_sub.add_parser("init")
    identity_init.add_argument("--alias", default="default")
    identity_init.add_argument("--overwrite", action="store_true")
    identity_init.add_argument("--dangerously-export-recovery")
    identity_recover = identity_sub.add_parser("recover")
    identity_recover.add_argument("--alias", default="default")
    identity_recover.add_argument("--private-key-file")
    identity_recover.add_argument("--overwrite", action="store_true")
    identity_recover.add_argument("--profile")
    identity_recover.add_argument("--device-name", default="recovered-device")
    identity_show = identity_sub.add_parser("show")
    identity_show.add_argument("--alias", default="default")
    identity_device = identity_sub.add_parser("device")
    identity_device.add_argument("--alias", default="default")
    identity_revoke = identity_sub.add_parser("revoke")
    identity_revoke.add_argument("device_id", nargs="?")
    identity_revoke.add_argument("--profile")
    identity_revoke.add_argument("--forget-local", action="store_true")
    for action in ("login", "logout"):
        command = identity_sub.add_parser(action)
        command.add_argument("--profile")
    identity_enroll = identity_sub.add_parser("enroll", help="claim a User invite read from stdin")
    identity_enroll.add_argument("--invite-stdin", action="store_true", required=True)
    identity_enroll.add_argument("--display-name", required=True)
    identity_enroll.add_argument("--device-name", default="primary-device")
    identity_enroll.add_argument("--profile")
    identity_device_enroll = identity_sub.add_parser(
        "device-enroll", help="claim a Broker Device invite using the local Device key"
    )
    identity_device_enroll.add_argument("--invite-stdin", action="store_true", required=True)
    identity_device_enroll.add_argument("--device-name", default="broker-device")
    identity_device_enroll.add_argument("--profile")

    profile = sub.add_parser("profile")
    profile_sub = profile.add_subparsers(dest="profile_action", required=True)
    profile_add = profile_sub.add_parser("add")
    profile_add.add_argument("name")
    profile_add.add_argument("endpoint")
    profile_add.add_argument("--workspace")
    profile_add.add_argument("--identity", default="default")
    profile_add.add_argument("--no-use", action="store_true")
    profile_use = profile_sub.add_parser("use")
    profile_use.add_argument("name")
    profile_show = profile_sub.add_parser("show")
    profile_show.add_argument("name", nargs="?")
    profile_sub.add_parser("list")
    profile_endpoint_set = profile_sub.add_parser("endpoint-set")
    profile_endpoint_set.add_argument("endpoint")
    profile_endpoint_set.add_argument("--profile")

    gateway = sub.add_parser("gateway")
    gateway_sub = gateway.add_subparsers(dest="gateway_action", required=True)
    bootstrap = gateway_sub.add_parser("bootstrap")
    bootstrap.add_argument("--profile")
    bootstrap.add_argument("--display-name", required=True)
    bootstrap.add_argument("--device-name", default="primary-device")
    health = gateway_sub.add_parser("health")
    health.add_argument("--profile")

    service = sub.add_parser("service", help="manage a scoped API Service identity")
    service_sub = service.add_subparsers(dest="service_action", required=True)
    service_enroll = service_sub.add_parser(
        "enroll", help="claim a Service invite using a new independent key pair"
    )
    service_enroll.add_argument("--invite-stdin", action="store_true", required=True)
    service_enroll.add_argument("--name", required=True)
    service_enroll_storage = service_enroll.add_mutually_exclusive_group()
    service_enroll_storage.add_argument("--credentials-account")
    service_enroll_storage.add_argument("--credentials-file", type=Path)
    service_enroll.add_argument("--overwrite", action="store_true")
    service_enroll.add_argument(
        "--use", action="store_true", help="bind this profile to the enrolled Service"
    )
    service_enroll.add_argument("--profile")
    service_use = service_sub.add_parser(
        "use", help="bind a profile to locally stored Service credentials"
    )
    service_use.add_argument("service_id")
    service_use_source = service_use.add_mutually_exclusive_group()
    service_use_source.add_argument("--credentials-account")
    service_use_source.add_argument("--credentials-file", type=Path)
    service_use.add_argument("--profile")
    for action in ("login", "logout", "show", "revoke-local"):
        command = service_sub.add_parser(action)
        command.add_argument("--profile")
    service_key_sync = service_sub.add_parser("key-sync")
    service_key_sync.add_argument("--workspace")
    service_key_sync.add_argument("--key-version", type=int)
    service_key_sync.add_argument("--profile")

    workspace = sub.add_parser("workspace")
    workspace_sub = workspace.add_subparsers(dest="workspace_action", required=True)
    create = workspace_sub.add_parser("create")
    create.add_argument("name")
    create.add_argument("--broker-id")
    create.add_argument("--use", action="store_true")
    create.add_argument("--profile")
    listing = workspace_sub.add_parser("list")
    listing.add_argument("--profile")
    member_list = workspace_sub.add_parser(
        "member-list",
        help="list Workspace users, current activity, queued tasks, and Worker usage",
    )
    member_list.add_argument("--workspace", help="Workspace ID; defaults to the Profile binding")
    member_list.add_argument(
        "--include-revoked", action="store_true", help="include revoked memberships"
    )
    member_list.add_argument("--profile", help="local Profile to use")
    user_list = workspace_sub.add_parser(
        "user-list",
        help="alias for member-list: show Workspace users and current activity",
    )
    user_list.add_argument("--workspace", help="Workspace ID; defaults to the Profile binding")
    user_list.add_argument(
        "--include-revoked", action="store_true", help="include revoked memberships"
    )
    user_list.add_argument("--profile", help="local Profile to use")
    pool_create = workspace_sub.add_parser("pool-create")
    pool_create.add_argument("name")
    pool_create.add_argument("--workspace")
    pool_create.add_argument("--policy")
    pool_create.add_argument("--profile")
    pool_list = workspace_sub.add_parser("pool-list")
    pool_list.add_argument("--workspace")
    pool_list.add_argument("--profile")
    owner_migrate = workspace_sub.add_parser(
        "owner-migrate",
        help="explicitly pin a legacy pre-v0.3 Workspace Owner after a TOFU warning",
    )
    owner_migrate.add_argument("--workspace")
    owner_migrate.add_argument(
        "--accept-legacy-tofu",
        action="store_true",
        help="dangerously accept the displayed legacy Owner identity without a prompt",
    )
    owner_migrate.add_argument("--profile")
    key_sync = workspace_sub.add_parser("key-sync")
    key_sync.add_argument("--workspace")
    key_sync.add_argument("--key-version", type=int)
    key_sync.add_argument("--profile")
    key_grant = workspace_sub.add_parser("key-grant")
    key_grant.add_argument("recipient_id")
    key_grant.add_argument(
        "--recipient-type", choices=("user_recovery", "device", "service"), required=True
    )
    key_grant.add_argument("--workspace")
    key_grant.add_argument("--key-version", type=int)
    key_grant.add_argument("--profile")
    key_grant_enrollment = workspace_sub.add_parser(
        "key-grant-enrollment",
        help="grant the current Workspace key to the User claimed by an Enrollment",
    )
    key_grant_enrollment.add_argument("enrollment_id")
    key_grant_enrollment.add_argument("--workspace")
    key_grant_enrollment.add_argument("--verification-code")
    key_grant_enrollment.add_argument("--profile")
    key_rotate = workspace_sub.add_parser("key-rotate")
    key_rotate.add_argument("--workspace")
    key_rotate.add_argument("--expected-key-version", type=int)
    key_rotate.add_argument("--profile")
    authority_pin = workspace_sub.add_parser("authority-pin")
    authority_pin.add_argument("user_id")
    authority_pin.add_argument("--root-signing-public-key", required=True)
    authority_pin.add_argument("--root-key-id")
    authority_pin.add_argument("--workspace")
    authority_pin.add_argument("--profile")
    invite = workspace_sub.add_parser("invite")
    invite.add_argument("--workspace")
    invite.add_argument(
        "--kind",
        choices=("user", "broker_device", "service", "workspace_member"),
        required=True,
    )
    invite.add_argument(
        "--method", choices=("direct_invite", "invite_approval"), default="invite_approval"
    )
    invite.add_argument("--relationship")
    invite.add_argument("--scope", action="append", default=[])
    invite.add_argument("--subject-key-fingerprint")
    invite.add_argument("--ttl", type=int, default=1800)
    invite.add_argument(
        "--wait",
        action="store_true",
        help="wait for claim and automatically grant the Workspace key for a direct invite",
    )
    invite.add_argument("--timeout", type=float, default=600)
    invite.add_argument("--wait-interval", type=float, default=1)
    invite.add_argument("--verification-code")
    invite.add_argument("--profile")
    apply = workspace_sub.add_parser("apply")
    apply.add_argument("--workspace", required=True)
    apply.add_argument("--pool")
    apply.add_argument("--kind", required=True)
    apply.add_argument("--relationship")
    apply.add_argument("--display-name")
    apply.add_argument("--device-name")
    apply.add_argument("--profile")
    decide = workspace_sub.add_parser("decide")
    decide.add_argument("enrollment_id")
    decision = decide.add_mutually_exclusive_group(required=True)
    decision.add_argument("--approve", action="store_true")
    decision.add_argument("--reject", dest="approve", action="store_false")
    decide.add_argument("--verification-code")
    decide.add_argument("--workspace")
    decide.add_argument("--profile")
    enrollment_list = workspace_sub.add_parser("enrollment-list")
    enrollment_list.add_argument("--workspace")
    enrollment_list.add_argument("--state")
    enrollment_list.add_argument("--profile")
    allocation_list = workspace_sub.add_parser("allocation-list")
    allocation_list.add_argument("--workspace")
    allocation_list.add_argument("--profile")
    workspace_audit = workspace_sub.add_parser("audit")
    workspace_audit.add_argument("--workspace")
    workspace_audit.add_argument("--limit", type=int, default=100)
    workspace_audit.add_argument("--profile")

    join = sub.add_parser(
        "join",
        help="join a Workspace as a new User or claim a membership invite",
    )
    join.add_argument(
        "--invite-stdin",
        action="store_true",
        help="read the complete one-time Invite URI from stdin instead of a hidden prompt",
    )
    join.add_argument("--gateway", "--endpoint", dest="endpoint")
    join.add_argument("--display-name")
    join.add_argument("--device-name")
    join.add_argument("--identity")
    join.add_argument("--recovery-file", type=Path)
    join.add_argument("--pool", help="default Pool name or ID when the Workspace has several")
    join.add_argument("--resume", action="store_true", help="continue after approval or key grant")
    join.add_argument("--non-interactive", action="store_true")
    join.add_argument("--json", action="store_true")
    join.add_argument("--workflow-package", type=Path, help=argparse.SUPPRESS)
    join.add_argument("--profile")

    broker = sub.add_parser("broker")
    broker_sub = broker.add_subparsers(dest="broker_action", required=True)
    broker_create = broker_sub.add_parser("create")
    broker_create.add_argument("name")
    broker_create.add_argument("--profile")
    for action in ("list", "status"):
        command = broker_sub.add_parser(action)
        command.add_argument("--profile")
    broker_sub.add_parser(
        "local-status", help="inspect this Mac Home Broker process and runtime version"
    )
    broker_refresh = broker_sub.add_parser(
        "service-refresh", help="reload this Mac Home Broker with the current CLI version"
    )
    broker_refresh.add_argument("--profile")
    broker_device = broker_sub.add_parser("device")
    broker_device.add_argument("broker_id")
    broker_device.add_argument("device_id")
    broker_device.add_argument("--profile")
    broker_serve = broker_sub.add_parser("serve")
    broker_serve.add_argument("--broker-id", required=True)
    broker_serve.add_argument("--broker-device-id", required=True)
    broker_serve.add_argument("--profile")
    broker_serve.add_argument("--once", action="store_true")
    broker_serve.add_argument("--poll-seconds", type=float, default=5)
    broker_update = broker_sub.add_parser(
        "worker-update",
        help="upload a reviewed VGen Worker wheel and apply it when the Worker is idle",
    )
    broker_update.add_argument("wheel", type=Path)
    broker_update.add_argument("--worker", help="owned Worker name or ID; automatic when unique")
    broker_update.add_argument("--broker", help="Broker ID; defaults to this profile's Home Broker")
    broker_update.add_argument("--wait", action="store_true")
    broker_update.add_argument("--interval", type=float, default=2)
    broker_update.add_argument("--timeout", type=float, default=3600)
    broker_update.add_argument("--profile")
    broker_models = broker_sub.add_parser(
        "model-install",
        help="ask an owned Worker to install missing models from a verified workflow",
    )
    broker_models.add_argument(
        "workflow",
        nargs="?",
        default="vgen/minimax-h3-8step",
        help="installed workflow reference (default: vgen/minimax-h3-8step)",
    )
    broker_models.add_argument("--worker", help="owned Worker name or ID; automatic when unique")
    broker_models.add_argument("--broker", help="Broker ID; defaults to this profile's Home Broker")
    broker_models.add_argument(
        "--accept-license",
        action="append",
        default=[],
        metavar="LICENSE",
        help="accept a required model license; repeat for each distinct license",
    )
    broker_models.add_argument("--wait", action="store_true")
    broker_models.add_argument("--interval", type=float, default=2)
    broker_models.add_argument("--timeout", type=float, default=86_400)
    broker_models.add_argument("--profile")
    maintenance_list = broker_sub.add_parser(
        "maintenance-list", help="list maintenance jobs for an owned Worker"
    )
    maintenance_list.add_argument("--worker", help="owned Worker name or ID")
    maintenance_list.add_argument("--profile")
    maintenance_show = broker_sub.add_parser("maintenance-show", help="show a maintenance job")
    maintenance_show.add_argument("job_id")
    maintenance_show.add_argument("--profile")
    maintenance_cancel = broker_sub.add_parser(
        "maintenance-cancel", help="cancel a queued or running maintenance job"
    )
    maintenance_cancel.add_argument("job_id")
    maintenance_cancel.add_argument("--profile")

    worker = sub.add_parser("worker")
    worker_sub = worker.add_subparsers(dest="worker_action", required=True)
    worker_add = worker_sub.add_parser(
        "add",
        help="guide a universal Windows installer through secure Worker enrollment",
    )
    worker_add.add_argument("--name", default="Windows GPU Worker")
    worker_add.add_argument("--pool", help="Pool name (automatic when only one exists)")
    worker_add.add_argument("--manager-broker")
    worker_add.add_argument(
        "--rate",
        type=int,
        default=0,
        help="reserved microtokens-per-second rate for the future duration pricing formula",
    )
    worker_add.add_argument("--ttl", type=int, default=1800)
    worker_add.add_argument("--interval", type=float, default=2)
    worker_add.add_argument("--timeout", type=float, default=1800)
    worker_add.add_argument("--profile")
    worker_upgrade = worker_sub.add_parser(
        "upgrade",
        help="download the trusted stable Worker and apply it remotely when idle",
    )
    worker_upgrade.add_argument(
        "--worker", help="owned Worker name or ID; automatic when unique"
    )
    worker_upgrade.add_argument(
        "--broker", help="Broker ID; defaults to this profile's Home Broker"
    )
    worker_upgrade.add_argument("--wait", action="store_true")
    worker_upgrade.add_argument("--interval", type=float, default=2)
    worker_upgrade.add_argument("--timeout", type=float, default=3600)
    worker_upgrade.add_argument("--profile")
    worker_list = worker_sub.add_parser("list")
    worker_list.add_argument("--workspace")
    worker_list.add_argument("--profile")
    manager_set = worker_sub.add_parser(
        "manager-set", help="explicitly assign an owned Worker to a Broker"
    )
    manager_set.add_argument(
        "worker", nargs="?", help="owned Worker name or ID; automatic when unique"
    )
    manager_set.add_argument("--broker", help="Broker ID; defaults to this profile's Home Broker")
    manager_set.add_argument("--profile")
    worker_offer = worker_sub.add_parser("offer")
    worker_offer.add_argument("worker_id")
    worker_offer.add_argument("--pool", required=True)
    worker_offer.add_argument("--profile")
    allocation_approve = worker_sub.add_parser("approve-allocation")
    allocation_approve.add_argument("allocation_id")
    allocation_approve.add_argument("--profile")
    worker_leave = worker_sub.add_parser("leave")
    worker_leave.add_argument("worker_id")
    worker_leave.add_argument("--force", action="store_true")
    worker_leave.add_argument("--profile")
    worker_revoke = worker_sub.add_parser("revoke")
    worker_revoke.add_argument("worker_id")
    worker_revoke.add_argument("--profile")
    rate_propose = worker_sub.add_parser("rate-propose")
    rate_propose.add_argument("worker_id")
    rate_propose.add_argument("--workspace")
    rate_propose.add_argument(
        "--rate",
        type=int,
        required=True,
        help="reserved microtokens-per-second rate for the future duration pricing formula",
    )
    rate_propose.add_argument("--profile")
    rate_approve = worker_sub.add_parser("rate-approve")
    rate_approve.add_argument("rate_id")
    rate_approve.add_argument("--profile")
    worker_serve = worker_sub.add_parser("serve", help="run the encrypted Worker lease daemon")
    worker_serve.add_argument("--gateway-url")
    worker_serve.add_argument("--worker-id")
    worker_serve.add_argument("--identity-file", type=Path)
    worker_serve.add_argument("--identity-account")
    worker_serve.add_argument("--credentials-file", type=Path)
    worker_serve.add_argument("--credentials-keyring", action="store_true")
    worker_serve.add_argument("--session-token-file", type=Path)
    worker_serve.add_argument("--executor", default="comfyui")
    worker_serve.add_argument("--comfy-url", default="http://127.0.0.1:8188")
    worker_serve.add_argument("--comfy-output-dir", type=Path)
    worker_serve.add_argument("--comfy-model-root", type=Path)
    worker_serve.add_argument(
        "--comfy-policy-file",
        type=Path,
        default=(
            Path(os.environ["VGEN_COMFYUI_POLICY_FILE"])
            if os.environ.get("VGEN_COMFYUI_POLICY_FILE")
            else None
        ),
        help="local machine-admin ComfyUI graph allowlist",
    )
    worker_serve.add_argument("--announce", action="store_true")
    worker_serve.add_argument("--allow-http", action="store_true")
    worker_serve.add_argument("--local-artifact-root", type=Path, action="append", default=[])
    worker_serve.add_argument("--work-root", type=Path)
    worker_serve.add_argument("--lease-ttl", type=int, default=60)
    worker_serve.add_argument("--interval", type=float, default=5)
    worker_serve.add_argument("--once", action="store_true")
    worker_serve.add_argument("--json", action="store_true")

    workflow = sub.add_parser("workflow")
    workflow_sub = workflow.add_subparsers(dest="workflow_action", required=True)
    install = workflow_sub.add_parser("install")
    install.add_argument("source")
    install.add_argument("--allow-unsigned", action="store_true")
    install.add_argument(
        "--publisher-key",
        help="base64 Ed25519 publisher key obtained independently of a remote market index",
    )
    custom = workflow_sub.add_parser("custom")
    custom.add_argument("source")
    custom.add_argument("--allow-unsigned", action="store_true")
    workflow_sub.add_parser("list")
    for action in ("show", "verify"):
        command = workflow_sub.add_parser(action)
        command.add_argument("source")
    search = workflow_sub.add_parser("search")
    search.add_argument("query")
    search.add_argument("--index", required=True)
    remove = workflow_sub.add_parser("remove")
    remove.add_argument("workflow_id")
    remove.add_argument("version")
    remove.add_argument("--provenance", choices=("market", "custom"))
    sign = workflow_sub.add_parser("sign")
    sign.add_argument("source")
    sign.add_argument("--key-file", required=True)
    package = workflow_sub.add_parser("package")
    package.add_argument("source")
    package.add_argument("output")
    publish = workflow_sub.add_parser("publish")
    publish.add_argument("source")
    publish.add_argument("output")
    update = workflow_sub.add_parser("update")
    update.add_argument("workflow_id")
    update.add_argument("--index", required=True)

    task = sub.add_parser("task")
    task_sub = task.add_subparsers(dest="task_action", required=True)
    preflight = task_sub.add_parser(
        "preflight",
        help="check Worker, workflow capability, and rate readiness without reserving capacity",
    )
    preflight.add_argument(
        "prompt",
        nargs="?",
        default="VGen capability preflight",
        help="optional local-only sample prompt used to validate workflow parameters",
    )
    preflight.add_argument("--workflow", default="vgen/minimax-h3-8step")
    preflight.add_argument("--executor", default="comfyui")
    preflight.add_argument("--workspace")
    preflight.add_argument("--pool", help="Pool name (uses the Profile default when omitted)")
    preflight.add_argument("--image")
    preflight.add_argument("--last-image")
    preflight.add_argument("--parameter", "-p", action="append", default=[])
    preflight.add_argument("--profile")
    submit = task_sub.add_parser("submit")
    submit.add_argument("prompt")
    submit.add_argument("--workflow", default="vgen/minimax-h3-8step")
    submit.add_argument("--executor", default="comfyui")
    submit.add_argument("--workspace")
    submit.add_argument("--pool", help="Pool name (uses the Profile default when omitted)")
    submit.add_argument("--image")
    submit.add_argument("--last-image")
    submit.add_argument("--parameter", "-p", action="append", default=[])
    submit.add_argument("--priority", type=int, default=0)
    submit.add_argument("--idempotency-key")
    submit.add_argument(
        "--wait",
        action="store_true",
        help="wait for completion and download the decrypted result",
    )
    submit.add_argument("--output-dir", default=".")
    submit.add_argument("--overwrite", action="store_true")
    submit.add_argument("--wait-interval", type=float, default=2)
    submit.add_argument("--timeout", type=float, default=3600)
    submit.add_argument("--profile")
    for action in ("show", "cancel", "retry"):
        command = task_sub.add_parser(action)
        command.add_argument("task_id")
        command.add_argument("--profile")
    task_get = task_sub.add_parser("get")
    task_get.add_argument("task_id")
    task_get.add_argument("--output-dir", default=".")
    task_get.add_argument("--overwrite", action="store_true")
    task_get.add_argument("--profile")
    task_list = task_sub.add_parser(
        "list", help="show a short paginated task history; use task show for details"
    )
    task_list.add_argument("--workspace", help="Workspace ID; defaults to the Profile binding")
    task_list.add_argument("--state", help="only show tasks in this state")
    task_list.add_argument("--limit", type=int, default=20, help="summary rows per page (1-100)")
    task_list.add_argument("--cursor", help="opaque next-page cursor returned by the prior page")
    task_list.add_argument(
        "--sort", choices=("created", "updated", "priority", "state"), default="created"
    )
    task_list.add_argument("--order", choices=("asc", "desc"), default="desc")
    task_list.add_argument("--format", choices=("text", "json"), default="text")
    task_list.add_argument("--profile", help="local Profile to use")
    watch = task_sub.add_parser("watch")
    watch.add_argument("task_id")
    watch.add_argument("--interval", type=float, default=2)
    watch.add_argument("--timeout", type=float, default=3600)
    watch.add_argument("--profile")
    usage = task_sub.add_parser("usage")
    usage.add_argument("--workspace")
    usage.add_argument("--profile")

    usage_root = sub.add_parser("usage")
    usage_sub = usage_root.add_subparsers(dest="usage_action", required=True)
    usage_list = usage_sub.add_parser("list")
    usage_list.add_argument("--workspace")
    usage_list.add_argument("--limit", type=int, default=100)
    usage_list.add_argument("--profile")
    usage_show = usage_sub.add_parser("show")
    usage_show.add_argument("entry_id")
    usage_show.add_argument("--workspace")
    usage_show.add_argument("--limit", type=int, default=500)
    usage_show.add_argument("--profile")
    _enhance_cli_help(parser)
    return parser


def dispatch(args: argparse.Namespace) -> None:
    handlers = {
        "setup": setup_command,
        "upgrade": upgrade_command,
        "identity": _identity_command,
        "profile": _profile_command,
        "gateway": _gateway_command,
        "service": _service_command,
        "workspace": _workspace_command,
        "join": join_command,
        "broker": _broker_command,
        "worker": _worker_command,
        "workflow": _workflow_command,
        "task": _task_command,
        "usage": _usage_command,
    }
    handlers[args.command](args)


def main(argv: list[str] | None = None) -> int:
    try:
        dispatch(build_parser().parse_args(argv))
        return 0
    except VgenClientError as exc:
        print(f"{exc.code} {exc.name}: {exc}", file=sys.stderr)
        return exc.exit_code
    except ArtifactTransferError as exc:
        print(f"700002 STORAGE_UNAVAILABLE: {exc}", file=sys.stderr)
        return 5
    except VGenError as exc:
        code = int(exc.code)
        spec = get_error_spec(exc.code)
        print(f"{code} {exc.code.name}: {spec.message}", file=sys.stderr)
        return cli_exit_code(code, retry_action=spec.retry_action.value)
    except WorkspaceAuthorityError as exc:
        print(f"400003 KEY_MANIFEST_INVALID: {exc}", file=sys.stderr)
        return 7
    except (ProfileError, IdentityStoreError, WorkspaceKeyError, RegistryError, ValueError) as exc:
        print(f"600001 VALIDATION_FAILED: {exc}", file=sys.stderr)
        return 2
    except TimeoutError as exc:
        print(f"700001 GATEWAY_UNREACHABLE: {exc}", file=sys.stderr)
        return 5
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"900001 INTERNAL_ERROR: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
