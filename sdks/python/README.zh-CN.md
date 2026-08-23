# VGen Python SDK

[English](README.md) | 简体中文

`vgen-sdk` 提供 VGen API Service 所需的凭据、签名和端到端加密基础能力。它是一个完全独立
的包，不会导入或安装 VGen CLI、Gateway、Broker 或 Worker。

首个版本刻意不内置 HTTP 客户端和工作流构建器。应用可以继续使用自己的 HTTP 技术栈，SDK
只负责不应由接入方随意重复实现的协议和密码学操作。

## 安装

在本仓库中执行：

```bash
python -m pip install ./sdks/python
```

运行时依赖只有 `cryptography` 和 `PyNaCl`。

## 已支持的协议能力

- 读写现有 `vgen-service-credentials` version 1 凭据。
- 生成兼容的 Ed25519/X25519 Service 密钥和 `devkey_...` Key ID。
- 签署 Service 登录 Challenge，并构造 Challenge/Session 请求体。
- 按 VGen 约束的 RFC 9421 Profile 签署 HTTP 请求原始字节。
- 使用业务方提供的信任根验证 Key Manifest、Worker Owner Certificate 和 Workspace
  Allocation Proof。
- 使用 XChaCha20-Poly1305-IETF 加密小型任务 Payload。
- 使用 RFC 9180 HPKE Base、X25519、HKDF-SHA256 和 ChaCha20-Poly1305 为 Worker 和
  Service Reader 封装任务密钥。
- 保留底层 Workspace Key 和 Workspace Reader 原语，用于协议兼容。
- 构造规范的 Task/Workspace AAD。

SDK 使用与现有 VGen 实现及 Java SDK 相同的兼容向量测试 Wire Format 和密码学结果。

## 读取 Service 凭据

管理员可以继续通过现有 VGen 管理流程创建 Service 和凭据文件。业务应用只读取这份文件，
不需要 CLI Profile，也不会复用用户 Device 身份。

```python
from vgen_sdk import ServiceCredentials

credentials = ServiceCredentials.load("/run/secrets/vgen-service.json")

print(credentials.service_id)
print(credentials.workspace_id)
print(credentials.scopes)
```

在 POSIX 系统中，`load()` 只接受权限为 `0600` 的普通文件，并拒绝符号链接。`save()` 会以
`0600` 权限原子写入新文件：

```python
credentials.save("/run/secrets/vgen-service-copy.json")
```

凭据文件包含两把私钥，不要记录到日志、提交到代码仓库或发送给其他系统。

## Service 鉴权

SDK 只构造请求体，网络请求继续由应用自己的 HTTP 客户端发送。

```python
from vgen_sdk import (
    build_service_challenge_request,
    build_service_session_request,
)

challenge_request = build_service_challenge_request(credentials)
# POST /api/v1/auth/challenges，Body 使用 challenge_request

challenge_response = {
    "challenge_id": "ses_...",
    "challenge": "...",
    "principal_type": "service",
}

session_request = build_service_session_request(credentials, challenge_response)
# POST /api/v1/auth/sessions，Body 使用 session_request
```

Session 响应中包含短期 Bearer Token。只在内存中保存，不要打印。

## 签署变更请求

必须签署最终发送的原始 Body 字节。`path` 必须包含原始 Query String，顺序和编码也必须与
实际网络请求完全相同。

```python
from vgen_sdk import canonical_json, sign_http_request

body = canonical_json({"worker_tdk_envelope": "..."})
task_id = "tsk_aaaaaaaaaaaaaaaaaaaaaaaaaa"
signature_headers = sign_http_request(
    credentials.keys,
    method="POST",
    path=f"/api/v1/tasks/{task_id}/commit",
    body=body,
).to_headers()

headers = {
    "Authorization": f"Bearer {session_token}",
    "Content-Type": "application/json",
    "Vgen-Protocol-Version": "1",
    "Idempotency-Key": "order-123",
    **signature_headers,
}
```

签名后不要让 HTTP 客户端重新序列化 `body`。

## Service Reader Envelope 边界

当前 Gateway 不会向 Service 下发 Workspace Data Key。Service 应将 Task Data Key 再使用
HPKE 封装一次，接收方是自己的 X25519 公钥。Gateway 只把 `reader_envelope` 当作不透明数据
保存；Service 获取结果时再用自己的私钥打开。

Workspace Key 相关函数只作为底层兼容原语保留，供已经通过其他授权方式取得 Workspace
Envelope 的调用方使用。提供这些函数不代表当前 Gateway 已支持给 Service 下发 Workspace Key。

## 校验 Prepared Worker 和 Allocation

两项校验都通过后才能向 Worker 封装任务密钥。下面两把 Root Key 必须来自业务系统自己维护的
可信配置，不能直接采用未受信任的 Prepare 响应字段。

```python
from vgen_sdk import (
    build_allocation_proof_payload,
    verify_allocation_proof,
    verify_worker_owner_certificate,
)

worker = prepared["worker"]
if not verify_worker_owner_certificate(worker, trusted_worker_owner_root_key):
    raise ValueError("untrusted Worker owner certificate")

allocation = prepared["allocation"]
proof = allocation["proof"]
expected_allocation = build_allocation_proof_payload(
    allocation_id=allocation["id"],
    workspace_id=credentials.workspace_id,
    pool_id=pool_id,
    worker_id=worker["id"],
    worker_signing_public_key=worker["signing_public_key"],
    worker_encryption_public_key=worker["encryption_public_key"],
    worker_certificate=worker["certificate"],
    owner_consent_at=float(allocation["owner_consent_at"]),
    approver_root_key_id=proof["payload"]["approver_root_key_id"],
    issued_at=int(proof["payload"]["issued_at"]),
)
if not verify_allocation_proof(
    proof,
    trusted_workspace_admin_root_key,
    expected=expected_allocation,
):
    raise ValueError("untrusted Workspace allocation")
```

## 加密 Prepared Task

使用 `POST /api/v1/tasks/prepare` 返回的 ID。Payload 与 Reader AAD 使用
`content_attempt_id`；Worker 密钥封装使用当前 `attempt_id`。

```python
import json

from vgen_sdk import (
    HPKE_ALGORITHM,
    b64url_decode,
    encrypt_payload,
    generate_task_data_key,
    task_aad,
    unwrap_task_key,
    wrap_task_key,
)

task_key = generate_task_data_key()
content_attempt_id = prepared.get("content_attempt_id") or prepared["attempt_id"]
key_version = int(prepared["key_version"])

content_aad = task_aad(
    workspace_id=credentials.workspace_id,
    task_id=prepared["id"],
    attempt_id=content_attempt_id,
    key_version=key_version,
)
worker_wrap_aad = task_aad(
    workspace_id=credentials.workspace_id,
    task_id=prepared["id"],
    attempt_id=prepared["attempt_id"],
    key_version=key_version,
)

plaintext = json.dumps(
    {
        "workflow": workflow_graph,
        "input_bindings": [],
        "effective_parameters": parameters,
    },
    ensure_ascii=False,
    separators=(",", ":"),
).encode("utf-8")

encrypted_payload = encrypt_payload(task_key, plaintext, aad=content_aad)
worker_envelope = wrap_task_key(
    b64url_decode(prepared["worker"]["encryption_public_key"], expected_length=32),
    task_key,
    aad=worker_wrap_aad,
)
reader_envelope = wrap_task_key(
    credentials.keys.encryption_public_bytes(),
    task_key,
    aad=content_aad,
)

commit_body = {
    "encrypted_payload": json.dumps(encrypted_payload.to_dict(), separators=(",", ":")),
    "worker_tdk_envelope": json.dumps(worker_envelope.to_dict(), separators=(",", ":")),
    "reader_envelope": json.dumps(reader_envelope.to_dict(), separators=(",", ":")),
    "key_algorithm": HPKE_ALGORITHM,
    "artifacts": [],
    "artifact_receipts": [],
}
```

读取结果时，使用 Reader 响应重新构造同一份 Content AAD，并在本地打开不透明 Reader
Envelope：

```python
reader_task_key = unwrap_task_key(
    credentials.keys.encryption_private_key,
    json.loads(reader_response["reader_envelope"]),
    aad=content_aad,
)
```

SDK 负责验证签名和字段绑定；哪些 Owner Root Key 和 Workspace Root Key 值得信任，仍由业务
系统决定。

## 本地开发

在本目录执行：

```bash
python -m pytest
python -m ruff check .
```

测试会读取仓库根目录的 `tests/sdk_compat/vectors.json`。其中的私钥均为公开测试数据，禁止在
测试以外使用。
