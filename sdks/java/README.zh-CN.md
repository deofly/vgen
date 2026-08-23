# VGen Java SDK

[English](README.md)

面向 Java 17+ 的 VGen API Service 凭据、签名和端到端加密核心能力。SDK 兼容现有
`vgen-service-credentials` v1 文件，以及已在线运行的 CLI、Gateway、Worker 所使用的
协议格式。

本模块不包含 HTTP 客户端，也不修改现有运行组件。应用可以自由选择 HTTP 库，将 SDK
生成的请求体和请求头发送给 Gateway。

## 构建

目前从仓库源码安装：

```bash
cd sdks/java
mvn install
```

然后引用本地 Maven 依赖：

```xml
<dependency>
  <groupId>com.vgen</groupId>
  <artifactId>vgen-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

运行时只依赖 Jackson 和 Bouncy Castle。Bouncy Castle 用于实现协议所需的原始
Ed25519/X25519 和 ChaCha20-Poly1305 能力；SDK 不会安装全局安全 Provider。

## 读取 Service 凭据

先由管理员使用现有 CLI 创建并授权 Service，再通过密钥管理服务将生成的私有凭据文件
交给业务应用。不要将该文件提交到代码仓库。

```java
import com.vgen.sdk.ServiceCredentials;

import java.nio.file.Path;

ServiceCredentials credentials = ServiceCredentials.load(
    Path.of(System.getenv("VGEN_SERVICE_CREDENTIALS"))
);
```

加载器拒绝符号链接和非普通文件，在 POSIX 文件系统上要求权限为 `0600`，并验证凭据
格式、版本、私钥长度和派生后的 Key ID。它可以直接读取当前 VGen CLI 生成的凭据。

## 验证可信元数据

可信根必须来自应用配置或带外确认后已经固定的 Authority。禁止从同一份 Gateway 响应中
读取 Root Key 后立即将它当作可信根。

使用任何单独下发的签名 Key Manifest 前，先验证其签名：

```java
import com.vgen.sdk.VGenTrust;

if (!VGenTrust.verifyKeyManifest(signedManifest, pinnedIssuerRootPublicKey)) {
    throw new SecurityException("Key Manifest 签名无效");
}
```

验签只是第一步。应用还必须确认 Manifest 的 Kind、主体 ID、密钥、版本、算法和内容摘要，
都与实际请求的对象一致。当前公开 Service 链路不会向 Service 下发 Workspace Data Key，
因此任务读取链路不能依赖 Service WDK Grant。

为准备好的 Worker 封装 Task Data Key 前，必须同时验证 Worker Owner Certificate 和
Workspace Allocation Proof。`expectedAllocation` 应由应用选定的 Workspace、Pool、
Worker、Certificate、授权时间、可信审批人 Root ID 和签发时间构造，不能直接使用未经
校验的替代对象：

```java
if (!VGenTrust.verifyWorkerOwnerCertificate(worker, pinnedWorkerOwnerRootPublicKey)) {
    throw new SecurityException("Worker Owner Certificate 无效");
}

var expectedAllocation = VGenTrust.buildAllocationProofPayload(
    allocationId,
    workspaceId,
    poolId,
    workerId,
    workerSigningPublicKey,
    workerEncryptionPublicKey,
    workerCertificate,
    ownerConsentAt,
    VGenTrust.rootSigningKeyId(pinnedWorkspaceAdminRootPublicKey),
    allocationProofIssuedAt
);
if (!VGenTrust.verifyAllocationProof(
        allocationProof, pinnedWorkspaceAdminRootPublicKey, expectedAllocation)) {
    throw new SecurityException("Worker Allocation Proof 无效");
}
```

这些方法验证签名、Signer Key ID、Certificate 密钥绑定、Schema 和未来时间偏差，但不会
替应用建立信任。可信 Owner/Admin Root Key 和预期 Allocation 绑定必须由调用方提供。
底层验证器为了协议兼容允许省略或只传部分绑定，但生产环境披露 Task Key 前，必须传入
`buildAllocationProofPayload(...)` 返回的完整 Map。

## 完成 Service 鉴权

使用自己的 HTTP 客户端，将第一个 Map 提交到 `/api/v1/auth/challenges`。将响应中的
`challenge_id` 和 `challenge` 传给第二个方法，再把结果提交到
`/api/v1/auth/sessions`：

```java
import com.vgen.sdk.ServiceAuth;

var challengeBody = ServiceAuth.challengeRequest(credentials);

String challengeId = "ses_...";
String challenge = "...";
var sessionBody = ServiceAuth.sessionRequest(credentials, challengeId, challenge);
```

`sessionBody` 包含带上下文绑定的 Ed25519 签名，私钥不会离开应用。认证成功后，使用
Gateway 返回的短期 Session Token 作为 Bearer Token。

## 为写请求签名

VGen 写操作还要求受限的 RFC 9421 HTTP Message Signature。必须对最终发送的 UTF-8
请求体，以及包含原始 Query String 的准确请求目标签名：

```java
import com.vgen.sdk.CanonicalJson;
import com.vgen.sdk.HttpSignatures;

byte[] body = CanonicalJson.encode(requestBody);
var signature = HttpSignatures.sign(
    credentials.deviceKeys(),
    "POST",
    "/api/v1/tasks/tsk_aaaaaaaaaaaaaaaaaaaaaaaaaa/commit",
    body
);
signature.toMap().forEach(httpRequest::header);
```

签名后必须发送相同的 `body` 字节，不能再次序列化对象，否则会导致摘要和签名失效。

## 加密任务内容

Gateway 准备好任务后，根据返回的 ID 和 Key Version 构造 AAD。使用新的 Task Data Key
加密工作流内容，分别为 Worker 和 Service 自身的 X25519 密钥封装该密钥：

```java
import com.vgen.sdk.Aad;
import com.vgen.sdk.Base64Url;
import com.vgen.sdk.CanonicalJson;
import com.vgen.sdk.Hpke;
import com.vgen.sdk.PayloadCrypto;

import java.nio.charset.StandardCharsets;

byte[] taskAad = Aad.task(
    workspaceId, taskId, contentAttemptId, "payload", keyVersion
);
byte[] workerAad = Aad.task(
    workspaceId, taskId, assignedAttemptId, "payload", keyVersion
);

byte[] taskDataKey = PayloadCrypto.generateKey();
var encryptedPayload = PayloadCrypto.encrypt(taskDataKey, opaqueWorkflowBytes, taskAad);
var workerEnvelope = Hpke.wrapTaskKey(
    Base64Url.decode(workerEncryptionPublicKey, 32),
    taskDataKey,
    workerAad
);
var readerEnvelope = Hpke.wrapTaskKey(
    credentials.deviceKeys().encryptionPublicKey(),
    taskDataKey,
    taskAad
);

String encryptedPayloadWire = new String(
    CanonicalJson.encode(encryptedPayload.toMap()), StandardCharsets.UTF_8
);
String workerEnvelopeWire = new String(
    CanonicalJson.encode(workerEnvelope.toMap()), StandardCharsets.UTF_8
);
String readerEnvelopeWire = new String(
    CanonicalJson.encode(readerEnvelope.toMap()), StandardCharsets.UTF_8
);
```

将上述三个 JSON 字符串分别作为 Commit 请求的 `encrypted_payload`、
`worker_tdk_envelope` 和 `reader_envelope`。Reader Envelope 绑定当前独立
Service 身份；Gateway 只能接触密文，不能获得 Service 私钥或 `taskDataKey`。

对应的解密操作为：

```java
byte[] taskKey = Hpke.unwrapTaskKey(privateX25519Key, workerEnvelope, workerAad);
byte[] plaintext = PayloadCrypto.decrypt(taskKey, encryptedPayload, taskAad);

byte[] readerTaskKey = Hpke.unwrapTaskKey(
    credentials.deviceKeys().encryptionPrivateKey(), readerEnvelope, taskAad
);
```

`Hpke.wrapWorkspaceKey(...)`、`Hpke.unwrapWorkspaceKey(...)`、
`Aad.workspaceKey(...)` 和 `PayloadCrypto.wrapTaskKeyForWorkspace(...)` 继续作为现有协议
产物的底层兼容原语保留。当前 SDK 不提供 Service Workspace Data Key 下发，这些原语不
属于公开 Service 的任务读取链路。

## 安全注意事项

- 将 Service 凭据存入密钥管理服务，并遵循最小权限原则。
- 不要记录私钥、Task Key、明文 Prompt 或 Session Token。
- 每个任务必须生成新的 Task Data Key。
- AAD 不一致或认证标签校验失败时必须直接失败，不能降低校验强度重试。
- `tests/sdk_compat/vectors.json` 内的固定私钥和 Nonce 都是公开测试数据，禁止用于生产。

## 兼容性测试

```bash
cd sdks/java
mvn test
```

测试直接读取仓库根目录的 Python 参考向量，覆盖 Canonical JSON、Service 凭据、Key ID、
Challenge/HTTP 签名、任务和 Workspace AAD、签名 Manifest、Worker 所有权与 Allocation
Proof、XChaCha20-Poly1305、RFC 9180 HPKE Task/Service Reader 信封，以及底层 Workspace
兼容原语。
