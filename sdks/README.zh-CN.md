# VGen SDK

[English](README.md)

VGen SDK 在不导入 CLI 内部代码的情况下，为 API Service 提供可移植的凭据、签名和端到端加密基础能力。

- [Python SDK](python/README.zh-CN.md)
- [Java SDK](java/README.zh-CN.md)
- [字节级兼容性协议](../docs/zh-CN/sdk-compatibility.md)
- [共享兼容向量](../tests/sdk_compat/vectors.json)

SDK 是增量式客户端，不会替换或修改已上线的 CLI、Gateway、Broker 或 Worker 链路。两个语言实现发布前必须通过同一组固定向量，并与 VGen 已签发的凭据和任务保持 Wire Format 兼容。

兼容向量中的所有私钥都是公开测试数据，绝不能作为真实凭据使用。

## 使用现有 CLI 完成一次性凭据 Provision

Provision 仍由管理员完成：创建独立的 API Service 身份，不复用管理员的 User Device 身份。

管理员先创建带 Scope 的一次性 Service Invite。必须通过安全渠道传递完整 Invite URI，并将其视为 Bearer Secret：

```bash
vgen workspace invite \
  --kind service \
  --method direct_invite \
  --scope task:submit \
  --scope task:read \
  --scope task:cancel \
  --workspace <workspace_id> \
  --profile <admin_profile>
```

在 Provision 主机上，通过标准输入传入完整 URI，并写入私有凭据文件。这里刻意不使用 `--use`：

```bash
read -r -s VGEN_SERVICE_INVITE
printf '\n'
printf '%s\n' "$VGEN_SERVICE_INVITE" | \
  vgen service enroll \
    --invite-stdin \
    --name 'render-service' \
    --credentials-file /secure/path/vgen-service.json \
    --profile <gateway_profile>
unset VGEN_SERVICE_INVITE
```

Enrollment 完成后，业务应用直接加载 `vgen-service.json`。上述命令中的 CLI Profile 只在这一次用于选择 Gateway 和校验 Invite Authority；没有使用 `--use`，因此不会把该 Profile 绑定成 Service。后续 SDK 使用不依赖 CLI Profile、User Device 身份、用户恢复密钥或管理员 Session。

首版 SDK 刻意保持低层能力边界：提供凭据、Service Challenge/Session 请求构造、签名、AAD、HPKE 和 XChaCha 原语，不是完整的任务 HTTP Client。当前 Gateway 尚不支持将 Service 准入为新的 Workspace Data Key Recipient。API Service 改为使用语言手册中的直接 HPKE Reader Envelope 保留自身的任务读取能力。Service Workspace Key 准入、Workflow 构建、媒体传输和 HTTP 编排不属于本次 SDK-only 变更。
