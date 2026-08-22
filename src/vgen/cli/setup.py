from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from vgen.crypto import export_recovery_file, sign_http_request
from vgen.market import WorkflowRegistry

from .auth import login_session
from .client import GatewayClient, VgenClientError
from .identity_store import DeviceIdentity, DeviceIdentityStore
from .macos_broker_service import install_macos_broker_service
from .profile import GatewayProfile, ProfileStore
from .session_store import SessionStore, StoredSession
from .workspace_authorities import WorkspaceAuthorityStore
from .workspace_envelopes import initialize_workspace_keys, sync_workspace_key

OFFICIAL_WORKFLOW_ID = "vgen/minimax-h3-8step"
OFFICIAL_WORKFLOW_VERSION = "1.0.0"
OFFICIAL_WORKFLOW_DIGEST = "bd15cace959f6330626b47c07195b6f8a016e334683969c0d5b044b24debcb93"


def _setup_idempotency_key(resource: str, **scope: str | None) -> str:
    """Derive a stable HTTP-header-safe key from the setup operation's UTF-8 scope."""

    if not resource or not resource.isascii() or not resource.replace("-", "").isalnum():
        raise ValueError("setup idempotency resource must be an ASCII identifier")
    material = json.dumps(
        scope,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"setup-{resource}:{hashlib.sha256(material).hexdigest()}"


def _status(args: Any, message: str) -> None:
    print(message, file=sys.stderr if args.json else sys.stdout)


def _prompt_text(
    value: str | None,
    *,
    label: str,
    default: str | None,
    non_interactive: bool,
) -> str:
    if value is not None:
        selected = value.strip()
    elif non_interactive:
        if default is None:
            raise ValueError(f"非交互初始化必须指定{label}")
        selected = default
    else:
        suffix = f" [{default}]" if default is not None else ""
        selected = input(f"{label}{suffix}: ").strip() or default or ""
    if not selected:
        raise ValueError(f"{label}不能为空")
    return selected


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


def prompt_bootstrap_code() -> str:
    print(
        "\n首次初始化需要部署 Gateway 的 ECS 上生成的一次性 Bootstrap code。\n"
        "请新开一个终端，SSH 登录 Gateway ECS，然后执行：\n\n"
        "  sudo cat /var/lib/vgen/bootstrap-code\n\n"
        "复制命令输出，回到这里粘贴。如果你没有 ECS SSH 权限，请联系 Gateway 管理员。\n"
        "初始化成功后，管理员可在 ECS 删除已使用的文件：\n\n"
        "  sudo rm -f /var/lib/vgen/bootstrap-code\n",
        file=sys.stderr,
    )
    return getpass.getpass("Bootstrap code（粘贴后按回车，输入不会显示）: ").strip()


def _read_bootstrap_code(args: Any) -> str:
    if args.bootstrap_code_file is not None:
        path = Path(args.bootstrap_code_file).expanduser()
        if not path.is_file() or path.is_symlink():
            raise ValueError("Bootstrap code 文件不存在或不是普通文件")
        if path.stat().st_mode & 0o077:
            raise ValueError("Bootstrap code 文件权限过宽；请先执行 chmod 600")
        code = path.read_text(encoding="utf-8").strip()
    elif args.bootstrap_code_stdin:
        code = sys.stdin.read().strip()
    elif args.non_interactive:
        raise ValueError("非交互初始化需要 --bootstrap-code-file 或 --bootstrap-code-stdin")
    else:
        code = prompt_bootstrap_code()
    if not code:
        raise ValueError("Bootstrap code 不能为空")
    return code


def _save_recovery_file(path: Path, mnemonic: str) -> Path:
    target = path.expanduser().resolve()
    if target.exists():
        raise ValueError(f"不会覆盖已有恢复文件: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(export_recovery_file(mnemonic))
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return target


def _prepare_identity(args: Any, store: DeviceIdentityStore) -> DeviceIdentity:
    if store.exists(args.identity):
        return store.load(args.identity)
    if args.non_interactive and args.recovery_file is None:
        raise ValueError("首次非交互初始化必须用 --recovery-file 指定恢复文件保存位置")
    if not args.non_interactive:
        answer = input(
            "下一步会显示一次 24 个英文恢复词。请准备离线抄写，准备好了吗？[y/N]: "
        ).strip()
        if answer.casefold() not in {"y", "yes"}:
            raise ValueError("尚未创建身份；准备好记录恢复词后重新运行 vgen setup")
    bundle, identity = store.initialize(args.identity)
    if args.recovery_file is not None:
        try:
            target = _save_recovery_file(Path(args.recovery_file), bundle.mnemonic)
        except Exception:
            store.delete(args.identity)
            raise
        _status(args, f"✓ 恢复文件已保存到 {target}（请离线备份后删除电脑上的副本）")
    else:
        print("\n仅显示这一次的 24 个恢复词，请按顺序离线保存：\n")
        print(bundle.mnemonic)
        print()
        expected = bundle.recovery_words[-1]
        confirmed = input("请输入你记录的最后一个单词以继续: ").strip().casefold()
        if confirmed != expected.casefold():
            store.delete(args.identity)
            raise ValueError("恢复词确认失败；未使用的本地身份已撤销，请重新运行并完整记录")
    return identity


def _default_workflow_path() -> Path:
    installed = (
        Path(__file__).resolve().parents[1]
        / "assets"
        / "workflows"
        / "vgen"
        / "minimax-h3-8step"
        / OFFICIAL_WORKFLOW_VERSION
    )
    if installed.is_dir():
        return installed
    # Editable source installs keep the canonical package at repository root.
    source = (
        Path(__file__).resolve().parents[3]
        / "workflows"
        / "vgen"
        / "minimax-h3-8step"
        / OFFICIAL_WORKFLOW_VERSION
    )
    if source.is_dir():
        return source
    raise ValueError("CLI 安装包缺少官方 MiniMax H3 工作流；请重新下载安装包")


def _install_official_workflow(args: Any) -> None:
    source = (
        Path(args.workflow_package).expanduser()
        if args.workflow_package
        else _default_workflow_path()
    )
    result = WorkflowRegistry().install(
        source,
        allow_unsigned=True,
        expected_digest=OFFICIAL_WORKFLOW_DIGEST,
    )
    if (
        result.manifest.id != OFFICIAL_WORKFLOW_ID
        or result.manifest.version != OFFICIAL_WORKFLOW_VERSION
        or result.manifest.publisher.id != "vgen"
    ):
        raise ValueError("安装包中的官方工作流身份不匹配")


def _bootstrap(
    args: Any,
    profile: GatewayProfile,
    identity: DeviceIdentity,
    *,
    display_name: str,
    device_name: str,
) -> GatewayProfile:
    if profile.user_id and profile.device_id:
        login_session(profile, identity)
        return ProfileStore().get(profile.name)
    code = _read_bootstrap_code(args)
    client = GatewayClient(profile)
    try:
        response = client.request(
            "POST",
            "/api/v1/auth/bootstrap",
            json_body={
                "bootstrap_code": code,
                "display_name": display_name,
                **_device_registration(identity, name=device_name),
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
    if not session.token or not session.user_id or not session.device_id:
        raise ValueError("Gateway 返回了不完整的初始化结果")
    SessionStore().save(profile.name, session)
    return ProfileStore().update_binding(
        profile.name,
        user_id=session.user_id,
        device_id=session.device_id,
    )


def _authenticated_client(profile: GatewayProfile, identity: DeviceIdentity) -> GatewayClient:
    session = SessionStore().load(profile.name)
    if session is None:
        session = login_session(profile, identity)
    return GatewayClient(
        profile,
        session_token=session.token,
        signer=_signer(identity),
        token_refresher=lambda: login_session(profile, identity).token,
    )


def _wait_for_home_broker(
    profile: GatewayProfile,
    identity: DeviceIdentity,
    *,
    broker_id: str,
    broker_device_id: str,
    seen_after: float,
    timeout: float = 12.0,
) -> bool:
    deadline = time.monotonic() + timeout
    client = _authenticated_client(profile, identity)
    try:
        while time.monotonic() < deadline:
            brokers = client.request("GET", "/api/v1/brokers")
            broker = next((item for item in brokers if item.get("id") == broker_id), None)
            devices = broker.get("devices", []) if isinstance(broker, dict) else []
            device = next(
                (item for item in devices if item.get("id") == broker_device_id),
                None,
            )
            if isinstance(device, dict) and float(device.get("last_seen_at") or 0) > seen_after:
                return True
            time.sleep(0.5)
        return False
    finally:
        client.close()


def _home_broker_last_seen(
    profile: GatewayProfile,
    identity: DeviceIdentity,
    *,
    broker_id: str,
    broker_device_id: str,
) -> float:
    client = _authenticated_client(profile, identity)
    try:
        brokers = client.request("GET", "/api/v1/brokers")
    finally:
        client.close()
    broker = next((item for item in brokers if item.get("id") == broker_id), None)
    devices = broker.get("devices", []) if isinstance(broker, dict) else []
    device = next((item for item in devices if item.get("id") == broker_device_id), None)
    return float(device.get("last_seen_at") or 0) if isinstance(device, dict) else 0


def _ensure_workspace_keys(
    client: GatewayClient,
    identity: DeviceIdentity,
    profile: GatewayProfile,
    workspace: dict[str, Any],
    *,
    newly_created: bool,
) -> None:
    workspace_id = str(workspace["id"])
    user_id = str(profile.user_id)
    WorkspaceAuthorityStore().pin(
        workspace_id=workspace_id,
        user_id=user_id,
        root_signing_public_key=identity.root_signing_public_key,
        root_key_id=identity.root_key_id,
        source="workspace_creation",
    )
    if newly_created:
        WorkspaceAuthorityStore().pin_owner(
            workspace_id=workspace_id,
            user_id=user_id,
            root_signing_public_key=identity.root_signing_public_key,
            root_key_id=identity.root_key_id,
            source="workspace_creation",
        )
        initialize_workspace_keys(client, identity, workspace)
        return
    try:
        sync_workspace_key(
            client,
            identity,
            workspace_id=workspace_id,
            user_id=user_id,
        )
    except ValueError as exc:
        if "no decryptable Workspace key envelope" not in str(exc):
            raise
        initialize_workspace_keys(client, identity, workspace)


def setup_command(args: Any) -> None:
    """Run the first-owner Mac setup without exposing internal resource IDs."""

    profile_store = ProfileStore()
    _, profiles = profile_store.load()
    existing = profiles.get(args.profile)
    endpoint = _prompt_text(
        args.endpoint,
        label="Gateway 地址",
        default=existing.endpoint if existing else None,
        non_interactive=args.non_interactive,
    )
    candidate = GatewayProfile(name=args.profile, endpoint=endpoint, key_ref=args.identity)
    if existing is not None:
        if existing.principal_type != "device":
            raise ValueError("同名 profile 已绑定 API Service，不能用于 Home Broker")
        if (
            existing.endpoint != candidate.endpoint
            or (existing.key_ref or "default") != args.identity
        ):
            raise ValueError("同名 profile 已存在且配置不同；不会覆盖，请改用 --profile")
        profile = existing
    else:
        profile = candidate

    preflight = GatewayClient(profile)
    try:
        health = preflight.health()
    except VgenClientError as exc:
        if exc.status_code == 404:
            raise ValueError("这个地址还没有启用 Gateway v1，请先完成 ECS 一键部署") from None
        raise
    finally:
        preflight.close()
    if not isinstance(health, dict) or health.get("ok") is not True:
        raise ValueError("Gateway 健康检查未通过")
    if existing is not None:
        profile_store.use(profile.name)
    else:
        profile_store.put(profile)
    _status(args, "✓ Gateway 已连接")

    _install_official_workflow(args)
    _status(args, "✓ MiniMax H3 8-step 工作流已就绪")

    if profile.user_id and profile.device_id:
        display_name = args.display_name or "已注册用户"
    else:
        display_name = _prompt_text(
            args.display_name,
            label="你的显示名称",
            default=getpass.getuser() or "VGen User",
            non_interactive=args.non_interactive,
        )
    workspace_name = _prompt_text(
        args.workspace_name,
        label="工作空间名称",
        default="我的工作空间",
        non_interactive=True,
    )
    pool_name = _prompt_text(
        args.pool_name,
        label="GPU 资源池名称",
        default="默认 GPU 池",
        non_interactive=True,
    )
    broker_name = _prompt_text(
        args.broker_name,
        label="Home Broker 名称",
        default="我的 Home Broker",
        non_interactive=True,
    )
    device_name = _prompt_text(
        args.device_name,
        label="这台 Mac 的名称",
        default=platform.node() or "Mac",
        non_interactive=True,
    )

    identity = _prepare_identity(args, DeviceIdentityStore())
    profile = _bootstrap(
        args,
        profile,
        identity,
        display_name=display_name,
        device_name=device_name,
    )
    _status(args, "✓ 用户身份已连接（私钥只保存在这台 Mac 的钥匙串）")

    client = _authenticated_client(profile, identity)
    try:
        broker: dict[str, Any] | None = None
        if not args.no_home_broker:
            if profile.home_broker_id and profile.home_broker_device_id:
                broker = {
                    "id": profile.home_broker_id,
                    "broker_device": {"id": profile.home_broker_device_id},
                }
            else:
                broker = client.request(
                    "POST",
                    "/api/v1/brokers",
                    json_body={"name": broker_name, "device_id": profile.device_id},
                    idempotency_key=_setup_idempotency_key(
                        "broker",
                        root_key_id=identity.root_key_id,
                        profile_name=profile.name,
                        broker_name=broker_name,
                        device_id=profile.device_id,
                    ),
                )
                broker_device = broker.get("broker_device") or {}
                if not broker.get("id") or not broker_device.get("id"):
                    raise ValueError("Gateway 未返回完整的 Home Broker 绑定")
                profile = profile_store.update_binding(
                    profile.name,
                    home_broker_id=str(broker["id"]),
                    home_broker_device_id=str(broker_device["id"]),
                )

        newly_created = False
        if profile.default_workspace:
            workspaces = client.request("GET", "/api/v1/workspaces")
            workspace = next(
                (item for item in workspaces if item.get("id") == profile.default_workspace),
                None,
            )
            if workspace is None:
                raise ValueError("本地默认工作空间已不存在；请换一个 profile 重新初始化")
        else:
            workspace = client.request(
                "POST",
                "/api/v1/workspaces",
                json_body={
                    "name": workspace_name,
                    "founder_broker_id": broker.get("id") if broker else None,
                },
                idempotency_key=_setup_idempotency_key(
                    "workspace",
                    root_key_id=identity.root_key_id,
                    profile_name=profile.name,
                    workspace_name=workspace_name,
                    founder_broker_id=str(broker["id"]) if broker else None,
                ),
            )
            profile = profile_store.update_binding(
                profile.name,
                default_workspace=str(workspace["id"]),
            )
            newly_created = True
        _ensure_workspace_keys(
            client,
            identity,
            profile,
            workspace,
            newly_created=newly_created,
        )

        if profile.default_pool:
            pools = client.request(
                "GET",
                f"/api/v1/workspaces/{profile.default_workspace}/pools",
            )
            pool = next((item for item in pools if item.get("id") == profile.default_pool), None)
            if pool is None:
                raise ValueError("本地默认 GPU 资源池已不存在；请换一个 profile 重新初始化")
        else:
            pool = client.request(
                "POST",
                f"/api/v1/workspaces/{profile.default_workspace}/pools",
                json_body={"name": pool_name, "policy": {}},
                idempotency_key=_setup_idempotency_key(
                    "pool",
                    workspace_id=profile.default_workspace,
                    profile_name=profile.name,
                    pool_name=pool_name,
                ),
            )
            profile = profile_store.update_binding(
                profile.name,
                default_pool=str(pool["id"]),
            )
    finally:
        client.close()

    broker_service = "未启用"
    if not args.no_home_broker and not args.no_broker_service:
        if sys.platform == "darwin":
            previous_seen_at = _home_broker_last_seen(
                profile,
                identity,
                broker_id=str(profile.home_broker_id),
                broker_device_id=str(profile.home_broker_device_id),
            )
            service = install_macos_broker_service(
                profile_name=profile.name,
                broker_id=str(profile.home_broker_id),
                broker_device_id=str(profile.home_broker_device_id),
            )
            if not service.loaded:
                reason = f"（{service.error}）" if service.error else ""
                raise ValueError(
                    f"Home Broker 已配置但未能启动{reason}；"
                    f"请查看 {service.plist_path} 后重试"
                )
            if not _wait_for_home_broker(
                profile,
                identity,
                broker_id=str(profile.home_broker_id),
                broker_device_id=str(profile.home_broker_device_id),
                seen_after=previous_seen_at,
            ):
                raise ValueError(
                    "Home Broker 已加载但未能在 12 秒内上线；请检查 macOS 钥匙串提示和日志"
                )
            broker_service = "在线"
        else:
            broker_service = "已创建；自动常驻当前仅支持 macOS"

    if args.json:
        print(
            __import__("json").dumps(
                {
                    "ready": True,
                    "profile": asdict(profile),
                    "workflow": f"{OFFICIAL_WORKFLOW_ID}@{OFFICIAL_WORKFLOW_VERSION}",
                    "home_broker_service": broker_service,
                    "next_command": "vgen worker bundle",
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return
    workspace_display = str(workspace.get("name") or workspace_name)
    pool_display = str(pool.get("name") or pool_name)
    print("\n初始化完成")
    print(f"  Gateway: {profile.endpoint}")
    print(f"  工作空间: {workspace_display}")
    print(f"  GPU 资源池: {pool_display}")
    print(f"  Home Broker: {broker_service}")
    print("\n下一步在这台 Mac 上运行：vgen worker bundle")
