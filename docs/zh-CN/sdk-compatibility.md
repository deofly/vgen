# SDK 兼容性协议

[English](../sdk-compatibility.md)

本文定义 VGen Python SDK 与 Java SDK 共同遵守的字节级协议。它从已经上线的 CLI、Gateway 和 Worker 协议中提取，不改变这些运行链路。SDK 的实现必须保持增量式：可以调用现有 API，但不能为了简化 SDK 而改变既有请求、密文、凭据格式或运行行为。

可执行示例的唯一基准是 [`tests/sdk_compat/vectors.json`](../../tests/sdk_compat/vectors.json)。其中所有私钥和秘密都是公开测试材料，绝不能用于测试以外的环境。

## 本次交付范围

首版 SDK 只提供跨语言的低层协议原语，不新增或修改 Gateway Endpoint，不负责 Workflow 构建、媒体传输、Trust Pin 管理，也不是完整的任务 HTTP Client。这些原语已足以让应用构造现有 Service 任务链路中的加密部分。当前 Gateway 尚不支持将 API Service 准入为新的 Workspace Data Key Recipient，因此公开 Service 链路使用下文的直接 HPKE Reader Envelope。Workspace Key 相关章节仅作为已获授权协议产物的兼容原语。向已准备的 Worker 披露 Task Data Key 前，仍必须验证 Worker Certificate 和 Allocation Proof。

## API Service 身份

API Service 拥有独立的 `service_id`、签名密钥、加密密钥、权限范围和 Workspace 归属，不复用用户设备身份、CLI Profile、用户恢复密钥、Worker 凭据或它们的钥匙串记录。

稳定凭据格式继续使用 `vgen-service-credentials` version 1：

```json
{
  "format": "vgen-service-credentials",
  "version": 1,
  "service_id": "svc_...",
  "workspace_id": "wsp_...",
  "name": "render-service",
  "scopes": ["task:read", "task:submit"],
  "enrollment_id": "enr_...",
  "device_keys": {
    "format": "vgen-device-keys",
    "version": 1,
    "key_id": "devkey_...",
    "signing_private_key": "...",
    "encryption_private_key": "..."
  }
}
```

`device_keys` 是现有 Service 密钥对的线上字段名，并不表示 Service 复用了用户设备身份。重命名会破坏已签发凭据，因此 SDK 必须保留该字段。

在支持 POSIX 权限的平台上，凭据文件只能由所有者读取（`0600`），不得跟随符号链接，也不得写入日志。写入时使用键名按字典序排列的紧凑 JSON、ASCII 转义，并在末尾保留一个 LF 字节。读取时可以接受无意义空白和不同对象字段顺序，但必须校验格式、版本、密钥长度和派生出的 `key_id`。

## 通用编码规则

- 文本统一使用 UTF-8。
- JSON 中的二进制字段使用 RFC 4648 URL-safe Base64，省略 `=` padding。
- RFC 9421 的 `Content-Digest` 和 `Signature` 使用带 padding 的标准 Base64。
- Ed25519、X25519 的公私钥均使用 32 字节 raw 格式。
- XChaCha20-Poly1305 使用 32 字节密钥和 24 字节 nonce。
- 签名对象中的整数必须按整数编码，不能使用浮点数。

签名 JSON 使用现有 VGen canonical JSON 规则：

1. 每一级对象键名都按字典序排列。
2. JSON 字符串外不输出空白。
3. 非 ASCII 文本直接编码为 UTF-8。
4. 拒绝 NaN 和无穷大。

这套规则不是完整 RFC 8785。SDK 在签署协议对象前，必须先通过固定 canonical JSON 向量。

## Key ID 与 Challenge 签名

对于 raw Ed25519 公钥 `pk`：

```text
device key id = "devkey_" + base64url_no_pad(
  SHA-256("vgen-device-key-id-v1" || 0x00 || pk)[0:20]
)

root key id = "root_" + base64url_no_pad(
  SHA-256("vgen-root-key-id-v1" || 0x00 || pk)[0:20]
)
```

API Service 对 Gateway Challenge 进行 Ed25519 签名时，准确输入为：

```text
UTF8("vgen-message-signature-v1") || 0x00 || UTF8(challenge)
```

响应中的签名使用无 padding Base64url。Challenge 有效期短且只能使用一次；SDK 遇到已消费或过期的 Challenge 时必须重新申请，不能复用后重试。

## Root 信任、Worker 证书与 Allocation Proof

用户或管理员的 Root Signing Key 是独立于 API Service 密钥的信任根。SDK 必须通过已鉴权或本地 Pin 的 Authority 获得可信 Root Public Key，不能仅因为同一个 Gateway 响应中附带了某个 Root Key 就直接信任它。

通用 Signed Key Manifest 的形状为：

```json
{
  "manifest": { "...": "..." },
  "signer_key_id": "root_...",
  "signature": "..."
}
```

Ed25519 的准确签名输入为：

```text
UTF8("vgen-key-manifest-v1") || 0x00 || canonical_json(manifest)
```

校验时先从可信 Root Public Key 派生 `signer_key_id`，不一致时必须拒绝，再验证签名。

Worker Owner Certificate 是一种专用 Key Manifest，其 Manifest 必须准确绑定以下字段：

```json
{
  "version": 1,
  "kind": "vgen-worker-owner-certificate",
  "owner_root_key_id": "root_...",
  "worker_key_id": "devkey_...",
  "worker_signing_public_key": "...",
  "worker_encryption_public_key": "...",
  "issued_at": 1787490000
}
```

校验方必须检查 Root 签名、`owner_root_key_id`、根据当前 Worker Signing Key 派生的 `worker_key_id`，以及当前 Worker 的两把公钥是否逐字一致。只有签名正确还不够；替换任意一把 Worker Key 都必须失败。

Allocation Proof 使用的证书摘要覆盖完整 Signed Certificate，而不只是 Manifest：

```text
"sha256:" + lowercase_hex(SHA-256(canonical_json(certificate)))
```

Workspace Allocation Proof 使用 `vgen-workspace-allocation-proof-v1` 作为签名 Context，并绑定以下全部字段：

```text
version, kind, allocation_id, workspace_id, pool_id, worker_id,
worker_signing_public_key, worker_encryption_public_key,
worker_certificate_digest, owner_consent_at_ms,
approver_root_key_id, issued_at
```

`kind` 固定为 `vgen-workspace-worker-allocation`，`owner_consent_at_ms` 必须是整数。校验方必须根据当前选择的 Workspace、Pool、Worker、证书和授权时间重新构造完整 Payload，要求所有字段准确一致，校验已 Pin 的 Approver Root Key ID，再验证带 Context 的 Ed25519 签名。在向 Worker 封装 Task Data Key 前，任何绑定值发生变化都必须失败，包括只替换 Pool ID 或 Worker Key。

## HTTP 请求签名

鉴权写请求使用现有受限 RFC 9421 Profile。覆盖组件及顺序固定为：

```text
("@method" "@path" "content-digest")
```

签名参数顺序也固定为：

```text
created;nonce;keyid;alg="ed25519"
```

`@method` 使用大写；`@path` 是以 `/` 开头的准确 ASCII request target，存在查询参数时必须包含未经重组的原始 query string。`Content-Digest` 是准确 HTTP body 字节的 SHA-256。计算 digest 和签名后，不得再次序列化请求体。

每个签名请求必须使用新的密码学安全随机 Base64url nonce 和当前 Unix 时间戳。兼容向量中的固定时间与 nonce 只用于确定性测试。

## Task AAD 与 Payload 加密

任务 Payload 和 Artifact 使用包含以下准确字段的 canonical AAD：

```json
{
  "protocol_version": "v1",
  "workspace_id": "wsp_...",
  "task_id": "tsk_...",
  "attempt_id": "atm_...",
  "artifact_id": "payload",
  "key_version": 1
}
```

AAD 字节是该对象的 canonical JSON。Payload 使用与 libsodium 兼容的 XChaCha20-Poly1305-IETF，序列化格式为：

```json
{
  "algorithm": "XChaCha20-Poly1305-IETF",
  "nonce": "<24-byte base64url nonce>",
  "ciphertext": "<ciphertext followed by the 16-byte tag>"
}
```

生产代码必须生成新的随机 32 字节 Task Data Key 和随机 nonce，绝不能复用同一组 `(key, nonce)`。

## HPKE Envelope

VGen 使用 RFC 9180 HPKE Base mode，套件固定为：

```text
KEM  = DHKEM(X25519, HKDF-SHA256)  0x0020
KDF  = HKDF-SHA256                  0x0001
AEAD = ChaCha20-Poly1305            0x0003
```

算法标识为 `HPKE-Base-X25519-HKDF-SHA256-ChaCha20Poly1305`。Envelope 保存 32 字节 encapsulated public key 和 AEAD ciphertext，两者都使用无 padding Base64url。

封装 Task Data Key 时：

```text
info = UTF8("vgen-task-key-wrap-v1") || 0x00 || SHA-256(task_aad)
aad  = task_aad
```

在协议原语层，为已绑定 Recipient 封装 Workspace Data Key 时：

```text
info = UTF8("vgen-workspace-key-wrap-v1") || 0x00 || SHA-256(workspace_key_aad)
aad  = workspace_key_aad
```

当前绑定接收方的 Workspace AAD 使用 canonical JSON，包含 `protocol_version: "v2"`、`workspace_id`、`recipient_type`、`recipient_id`、`key_version` 和 64 字符小写 `recipient_binding_digest`。SDK 可以读取不含 binding digest 的旧 v1 Envelope。创建并分发新的 Service-bound Envelope 需要未来的 Service Recipient Admission 流程，不属于本次 SDK 交付。

HPKE seal 本身具有随机性。向量中的 sender ephemeral private key 只用于各 SDK 内部运行确定性兼容测试；生产公开 API 不能允许调用方指定 ephemeral key。

## API Service 直接 Reader Envelope

API Service 在本地生成 Task Data Key 后，可以在不依赖 Workspace Data Key 的情况下保留自身读取能力：使用独立 `vgen-service-credentials` 中的 X25519 Public Key，按照上文相同的 Task Key HPKE `info` 和 Task AAD，直接封装 Task Data Key。结果是普通 HPKE Envelope；Service 随后使用凭据中的 Encryption Private Key 解封。

该直接 Reader 原语不会向其他 Principal 授权，也不能替代 Workspace Recipient Admission；首版 SDK 仍不因此增加任务 HTTP Client。固定 `service_reader` 向量用于证明 Python、Java 和线上密码原语对该 Envelope 的解释完全一致。

## Workspace Reader Envelope

Workspace Reader Envelope 使用带版本的 Workspace Data Key，通过 XChaCha20-Poly1305 保护 Task Data Key。有效 AAD 为：

```text
UTF8("vgen-workspace-reader-envelope-v1") || 0x00 || task_aad
```

其序列化形状与 Payload ciphertext 相同。某个 Principal 通过已支持流程完成准入并获得 Workspace Data Key 后，可以据此恢复 Task Data Key，而 Gateway 仍然只负责路由密文。新 Service 的准入不属于当前 SDK 范围。

## 兼容性要求

Python 与 Java SDK 必须加载同一份根目录向量文件，并至少验证：

- canonical JSON 与 Base64url；
- Service 凭据解析及逐字节序列化；
- 公钥派生、Key ID 和 Challenge 签名；
- Root Key ID、通用 Key Manifest 及签名 Context；
- Worker Owner Certificate 的绑定字段和完整证书摘要；
- Workspace Allocation Proof 的全部绑定字段；
- RFC 9421 请求签名 Header；
- Task 与 Workspace AAD；
- XChaCha Payload 加解密；
- HPKE open 和仅用于测试的确定性 seal；
- 为凭据所属 API Service 创建的直接 HPKE Reader Envelope；
- Task Key、Workspace Key 和 Workspace Reader Envelope。

已有向量字段和预期值不可变，只能追加新案例。语义破坏必须升级向量版本并进行明确协议迁移，不能由某一个 SDK 静默引入。

仓库中的固定值可以使用线上 Python 密码学实现重新生成：

```bash
PYTHONPATH=src .venv/bin/python tests/sdk_compat/generate_vectors.py
```

使用当前线上实现运行检查：

```bash
pytest -q tests/sdk_compat
```
