from __future__ import annotations

import getpass
import json
import platform
import sys
from typing import Any

from vgen.crypto import sign_http_request
from vgen.protocol.user_enrollment import user_verification_code

from .auth import login_session
from .client import GatewayClient, VgenClientError
from .identity_store import DeviceIdentity, DeviceIdentityStore
from .profile import GatewayProfile, ProfileStore
from .setup import (
    OFFICIAL_WORKFLOW_ID,
    OFFICIAL_WORKFLOW_VERSION,
    _install_official_workflow,
    _prepare_identity,
)
from .user_enrollment import identity_registration_claim
from .workspace_authorities import (
    PinnedInvite,
    WorkspaceAuthorityStore,
    parse_pinned_invite_uri,
)
from .workspace_envelopes import sync_workspace_key


def _json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _read_invite(*, from_stdin: bool, non_interactive: bool) -> PinnedInvite:
    """Read the complete Invite URI without ever accepting it in argv.

    A terminal uses a hidden prompt.  Pipes and automation must opt in with
    --invite-stdin so an accidentally redirected stdin cannot be consumed.
    """

    if from_stdin:
        value = sys.stdin.read().strip()
    elif non_interactive or not sys.stdin.isatty():
        raise ValueError("非交互加入必须使用 --invite-stdin 读取邀请，不能把邀请放在命令参数中")
    else:
        value = getpass.getpass("粘贴一次性 Workspace 邀请（输入不会显示）: ").strip()
    if not value:
        raise ValueError("Workspace 邀请不能为空")
    return parse_pinned_invite_uri(value)


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


def _authenticated_client(profile: GatewayProfile, identity: DeviceIdentity) -> GatewayClient:
    session = login_session(profile, identity)
    return GatewayClient(
        ProfileStore().get(profile.name),
        session_token=session.token,
        signer=_signer(identity),
        token_refresher=lambda: login_session(ProfileStore().get(profile.name), identity).token,
    )


def _pin_invite_authority(
    invite: PinnedInvite, response_workspace_id: str, response_issuer_user_id: str
) -> None:
    if response_workspace_id != invite.authority.workspace_id:
        raise ValueError("Gateway enrollment Workspace does not match the trusted Invite URI")
    if response_issuer_user_id != invite.authority.user_id:
        raise ValueError("Gateway enrollment issuer does not match the trusted Invite URI")
    authority_store = WorkspaceAuthorityStore()
    authority_store.pin(
        workspace_id=invite.authority.workspace_id,
        user_id=invite.authority.user_id,
        root_signing_public_key=invite.authority.root_signing_public_key,
        root_key_id=invite.authority.root_key_id,
        source=invite.authority.source,
    )
    authority_store.pin_owner(
        workspace_id=invite.authority.workspace_id,
        user_id=invite.authority.user_id,
        root_signing_public_key=invite.authority.root_signing_public_key,
        root_key_id=invite.authority.root_key_id,
        source=invite.authority.source,
    )


def _selected_profile(args: Any, store: ProfileStore) -> tuple[str, GatewayProfile | None]:
    current, profiles = store.load()
    name = args.profile or current or "shared"
    return name, profiles.get(name)


def _preflight_profile(args: Any, store: ProfileStore) -> GatewayProfile:
    name, existing = _selected_profile(args, store)
    endpoint = (args.endpoint or (existing.endpoint if existing else None) or "").strip()
    if not endpoint:
        raise ValueError("首次加入需要 --gateway https://你的-Gateway-域名")
    identity_alias = args.identity or (existing.key_ref if existing else None) or name
    candidate = GatewayProfile(name=name, endpoint=endpoint, key_ref=identity_alias)
    if existing is not None:
        if existing.principal_type != "device":
            raise ValueError("同名 profile 已绑定 API Service，请改用另一个 --profile")
        if existing.endpoint != candidate.endpoint:
            raise ValueError("同名 profile 的 Gateway 地址不同；不会覆盖，请改用另一个 --profile")
        if (existing.key_ref or name) != identity_alias:
            raise ValueError("同名 profile 使用另一个本地身份；不会覆盖，请改用另一个 --profile")
        return existing

    client = GatewayClient(candidate)
    try:
        health = client.health()
    finally:
        client.close()
    if not isinstance(health, dict) or health.get("ok") is not True:
        raise ValueError("Gateway 健康检查未通过")
    store.put(candidate)
    return candidate


def _install_workflow(args: Any) -> str:
    _install_official_workflow(args)
    return f"{OFFICIAL_WORKFLOW_ID}@{OFFICIAL_WORKFLOW_VERSION}"


def _choose_pool(pools: Any, requested: str | None, *, non_interactive: bool) -> dict[str, Any]:
    choices = [item for item in pools if isinstance(item, dict) and item.get("id")]
    if requested:
        matches = [
            item
            for item in choices
            if requested in {str(item.get("id") or ""), str(item.get("name") or "")}
        ]
        if len(matches) != 1:
            raise ValueError(f"没有唯一匹配的 GPU 资源池: {requested}")
        return matches[0]
    if len(choices) == 1:
        return choices[0]
    if not choices:
        raise ValueError("Workspace 还没有 GPU 资源池；请让管理员先创建 Pool，然后运行 vgen join --resume")
    if non_interactive:
        raise ValueError("Workspace 有多个 GPU 资源池；请用 --pool 指定名称或 ID")
    print("请选择默认 GPU 资源池：")
    for index, item in enumerate(choices, 1):
        print(f"  {index}. {item.get('name') or item['id']}")
    selected = input("输入序号: ").strip()
    if not selected.isdigit() or not 1 <= int(selected) <= len(choices):
        raise ValueError("GPU 资源池序号无效")
    return choices[int(selected) - 1]


def _next_admin_key_command(profile: GatewayProfile, workspace_id: str) -> str:
    if profile.pending_enrollment:
        return (
            f"vgen workspace key-grant-enrollment {profile.pending_enrollment} "
            f"--workspace {workspace_id}"
        )
    return (
        f"vgen workspace key-grant {profile.user_id} --recipient-type user_recovery "
        f"--workspace {workspace_id}"
    )


def _finish_staged_join(
    args: Any,
    store: ProfileStore,
    profile: GatewayProfile,
    identity: DeviceIdentity,
    *,
    workflow: str,
) -> dict[str, Any]:
    workspace_id = profile.pending_workspace
    if not workspace_id or not profile.user_id or not profile.device_id:
        raise ValueError("没有可以继续的 Workspace 加入流程")

    client = _authenticated_client(profile, identity)
    try:
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
            return {
                "ready": False,
                "state": "approval_pending",
                "profile": profile.name,
                "enrollment_id": profile.pending_enrollment,
                "workflow": workflow,
                "next": "请等待 Workspace 管理员批准，然后运行 vgen join --resume",
            }
        try:
            key_result = sync_workspace_key(
                client,
                identity,
                workspace_id=workspace_id,
                user_id=profile.user_id,
            )
        except ValueError as exc:
            if "no decryptable Workspace key envelope" not in str(exc):
                raise
            return {
                "ready": False,
                "state": "workspace_key_pending",
                "profile": profile.name,
                "enrollment_id": profile.pending_enrollment,
                "workspace": workspace.get("name") or workspace_id,
                "workflow": workflow,
                "next": "请让 Workspace 管理员发放加密密钥，然后运行 vgen join --resume",
                "admin_command": _next_admin_key_command(profile, workspace_id),
            }
        pools = client.request("GET", f"/api/v1/workspaces/{workspace_id}/pools")
        pool = _choose_pool(pools, args.pool, non_interactive=args.non_interactive)
    finally:
        client.close()

    completed = store.update_binding(
        profile.name,
        default_workspace=workspace_id,
        default_pool=str(pool["id"]),
        pending_workspace=None,
        pending_enrollment=None,
    )
    return {
        "ready": True,
        "state": "active",
        "profile": completed.name,
        "gateway": completed.endpoint,
        "workspace": workspace.get("name") or workspace_id,
        "pool": pool.get("name") or pool["id"],
        "workflow": workflow,
        "workspace_key_version": key_result.get("key_version"),
        "next": 'vgen task submit "描述你想生成的视频" --wait',
    }


def _new_user_join(args: Any, store: ProfileStore, profile: GatewayProfile) -> dict[str, Any]:
    invite = _read_invite(
        from_stdin=bool(args.invite_stdin), non_interactive=bool(args.non_interactive)
    )
    identity_store = DeviceIdentityStore()
    prepare_args = type(
        "JoinIdentityArgs",
        (),
        {
            "identity": profile.key_ref or profile.name,
            "non_interactive": args.non_interactive,
            "recovery_file": args.recovery_file,
            "json": args.json,
        },
    )()
    identity = _prepare_identity(prepare_args, identity_store)
    display_name = (args.display_name or getpass.getuser() or "VGen User").strip()
    device_name = (args.device_name or platform.node() or "Mac").strip()
    if not display_name or not device_name:
        raise ValueError("显示名称和设备名称不能为空")
    claim, proof_signature = identity_registration_claim(
        identity,
        invite_id=invite.invite_id,
        display_name=display_name,
        device_name=device_name,
    )
    anonymous = GatewayClient(profile)
    try:
        response = anonymous.request(
            "POST",
            "/api/v1/auth/enroll",
            json_body={
                "invite_id": invite.invite_id,
                "secret": invite.secret,
                "claim": claim,
                "proof_signature": proof_signature,
            },
            auth=False,
        )
    finally:
        anonymous.close()
    enrollment = response["enrollment"]
    if enrollment.get("kind") != "user":
        raise ValueError("这个 Invite 不是新 User 加入邀请")
    if str(response.get("device", {}).get("id") or "") != identity.device_id:
        raise ValueError("Gateway enrollment Device does not match the local Device key")
    if not response.get("user", {}).get("id") or not enrollment.get("workspace_id"):
        raise ValueError("Gateway 返回了不完整的新 User 加入结果")
    workspace_id = str(enrollment["workspace_id"])
    _pin_invite_authority(invite, workspace_id, str(enrollment["issuer_user_id"]))
    profile = store.update_binding(
        profile.name,
        user_id=str(response["user"]["id"]),
        device_id=str(response["device"]["id"]),
        pending_workspace=workspace_id,
        pending_enrollment=str(enrollment["id"]),
        default_workspace=None,
        default_pool=None,
    )
    store.use(profile.name)
    # A pending User still owns an active Device and can obtain a key-bound
    # session.  Persist it now so resume never needs the consumed Invite.
    login_session(profile, identity)
    workflow = _install_workflow(args)
    verification_code = user_verification_code(claim)
    if enrollment.get("state") != "active":
        return {
            "ready": False,
            "state": "approval_pending",
            "profile": profile.name,
            "user_id": profile.user_id,
            "enrollment_id": profile.pending_enrollment,
            "workflow": workflow,
            "verification_code": verification_code,
            "next": "请等待 Workspace 管理员批准，然后运行 vgen join --resume",
        }
    result = _finish_staged_join(args, store, profile, identity, workflow=workflow)
    result["verification_code"] = verification_code
    return result


def _existing_user_workspace_join(
    args: Any,
    store: ProfileStore,
    profile: GatewayProfile,
) -> dict[str, Any]:
    """Claim a membership-only Invite and finish it through the staged join path."""

    invite = _read_invite(
        from_stdin=bool(args.invite_stdin), non_interactive=bool(args.non_interactive)
    )
    identity = DeviceIdentityStore().load(profile.key_ref or profile.name)
    display_name = (args.display_name or getpass.getuser() or "VGen User").strip()
    device_name = (args.device_name or platform.node() or "Mac").strip()
    claim, proof_signature = identity_registration_claim(
        identity,
        invite_id=invite.invite_id,
        display_name=display_name,
        device_name=device_name,
    )
    client = _authenticated_client(profile, identity)
    try:
        try:
            response = client.request(
                "POST",
                "/api/v1/enrollments/claim",
                json_body={
                    "invite_id": invite.invite_id,
                    "secret": invite.secret,
                    "claim": claim,
                    "proof_signature": proof_signature,
                },
                auth=True,
            )
        except VgenClientError as exc:
            if exc.code == 240001:
                raise ValueError(
                    "邀请无效、已过期，或不是 workspace_member 类型。现有 User 加入新的 "
                    "Workspace 时，请让管理员使用 `vgen workspace invite --kind "
                    "workspace_member ...` 重新邀请；user Invite 只用于创建新 User。"
                ) from None
            raise
    finally:
        client.close()

    if not isinstance(response, dict) or response.get("kind") != "workspace_member":
        raise ValueError(
            "Gateway 返回的不是 workspace_member Enrollment；现有 User 不会把 user Invite "
            "转换成 Workspace 成员邀请"
        )
    enrollment_id = str(response.get("id") or "")
    workspace_id = str(response.get("workspace_id") or "")
    issuer_user_id = str(response.get("issuer_user_id") or "")
    state = str(response.get("state") or "")
    if (
        enrollment_id != invite.invite_id
        or not workspace_id
        or not issuer_user_id
        or str(response.get("subject_user_id") or "") != profile.user_id
        or str(response.get("subject_id") or "") != profile.device_id
        or state not in {"pending", "active"}
    ):
        raise ValueError("Gateway 返回了不完整或不匹配的 workspace_member 加入结果")
    _pin_invite_authority(invite, workspace_id, issuer_user_id)
    staged = store.update_binding(
        profile.name,
        pending_workspace=workspace_id,
        pending_enrollment=enrollment_id,
    )
    store.use(staged.name)
    workflow = _install_workflow(args)
    verification_code = user_verification_code(claim)
    if state == "pending":
        return {
            "ready": False,
            "state": "approval_pending",
            "profile": staged.name,
            "user_id": staged.user_id,
            "enrollment_id": enrollment_id,
            "workflow": workflow,
            "verification_code": verification_code,
            "next": "请等待 Workspace 管理员批准，然后运行 vgen join --resume",
        }
    result = _finish_staged_join(args, store, staged, identity, workflow=workflow)
    result["verification_code"] = verification_code
    return result


def _print_result(result: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        _json(result)
        return
    if result["ready"]:
        print("\n加入完成")
        print(f"  Gateway: {result['gateway']}")
        print(f"  工作空间: {result['workspace']}")
        print(f"  GPU 资源池: {result['pool']}")
        print(f"  工作流: {result['workflow']}")
    else:
        labels = {
            "approval_pending": "邀请已领取，正在等待管理员批准",
            "workspace_key_pending": "成员关系已生效，正在等待管理员发放加密密钥",
        }
        print(f"\n{labels.get(result['state'], '加入流程尚未完成')}")
        if result.get("admin_command"):
            print("\n请把下面这条命令发给 Workspace 管理员：")
            print(result["admin_command"])
    if result.get("verification_code"):
        print("\n请通过可信渠道把下面的核验码告诉 Workspace Owner：")
        print(result["verification_code"])
    print(f"\n下一步：{result['next']}")


def join_command(args: Any) -> None:
    """Join as a new User, add an existing User to a Workspace, or resume either flow."""

    store = ProfileStore()
    _, existing = _selected_profile(args, store)
    if args.resume:
        if existing is None:
            raise ValueError("这个 profile 没有未完成的加入流程")
        if not existing.pending_workspace:
            raise ValueError("这个 profile 没有未完成的加入流程")
        store.use(existing.name)
        identity = DeviceIdentityStore().load(existing.key_ref or existing.name)
        workflow = _install_workflow(args)
        _print_result(
            _finish_staged_join(args, store, existing, identity, workflow=workflow),
            as_json=args.json,
        )
        return

    profile = _preflight_profile(args, store)
    if profile.pending_workspace:
        raise ValueError("已有未完成的加入流程；请运行 vgen join --resume")
    if bool(profile.user_id) != bool(profile.device_id):
        raise ValueError("这个 profile 的 User/Device 绑定不完整；不会创建重复 User")
    if profile.user_id and profile.device_id:
        result = _existing_user_workspace_join(args, store, profile)
        _print_result(result, as_json=args.json)
        return
    result = _new_user_join(args, store, profile)
    _print_result(result, as_json=args.json)
