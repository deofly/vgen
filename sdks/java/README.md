# VGen Java SDK

[中文](README.zh-CN.md)

Java 17+ primitives for a VGen API Service to use the existing Gateway protocol without
depending on the VGen CLI. The SDK reads the current `vgen-service-credentials` v1 format and
implements the same signing and end-to-end encryption wire formats used by the production
CLI, Gateway, and Worker.

This module contains no HTTP client and does not modify the existing runtime components. Your
application chooses its HTTP library and sends the maps and headers produced here.

## Build

The SDK is currently built from this repository:

```bash
cd sdks/java
mvn install
```

Then add the local artifact:

```xml
<dependency>
  <groupId>com.vgen</groupId>
  <artifactId>vgen-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

The only runtime dependencies are Jackson and Bouncy Castle. Bouncy Castle supplies the raw
Ed25519/X25519 and ChaCha20-Poly1305 primitives required for byte-compatible VGen encryption;
the SDK does not install a global security provider.

## Load Service credentials

Create and authorize the Service with the existing administrator CLI, then give the resulting
private credential file to the application through a secret manager. Do not commit that file.

```java
import com.vgen.sdk.ServiceCredentials;

import java.nio.file.Path;

ServiceCredentials credentials = ServiceCredentials.load(
    Path.of(System.getenv("VGEN_SERVICE_CREDENTIALS"))
);
```

The loader refuses symbolic links and non-regular files, enforces mode `0600` on POSIX file
systems, and checks the credential format, version, private-key lengths, and derived key ID. It
accepts files produced by the current VGen CLI and serializes them back in the same format.

## Verify trusted metadata

Trust roots must come from configuration or an out-of-band, previously pinned authority. Never
take a root key from the same Gateway response and immediately trust it.

When consuming any separately provisioned signed key manifest, verify it before using the
contained metadata:

```java
import com.vgen.sdk.VGenTrust;

if (!VGenTrust.verifyKeyManifest(signedManifest, pinnedIssuerRootPublicKey)) {
    throw new SecurityException("Key manifest signature is invalid");
}
```

Signature verification is only the first check. The application must also bind the manifest's
kind, subject IDs, keys, version, algorithm, and any content digest to the object it requested.
The current public Service flow does not provision a Workspace Data Key to the Service; do not
build the task reader path around a Service WDK grant.

Before wrapping a Task Data Key for a prepared Worker, verify both the Worker owner certificate
and its Workspace allocation. Build `expectedAllocation` from the Workspace, Pool, Worker,
certificate, consent timestamp, trusted approver root ID, and issued time selected by the
application—not from an unchecked replacement object:

```java
if (!VGenTrust.verifyWorkerOwnerCertificate(worker, pinnedWorkerOwnerRootPublicKey)) {
    throw new SecurityException("Worker owner certificate is invalid");
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
    throw new SecurityException("Worker allocation proof is invalid");
}
```

The helpers verify signatures, signer key IDs, certificate key bindings, schema, and future-time
limits. They never establish authority: the caller remains responsible for supplying the trusted
owner/admin root keys and for choosing the expected allocation bindings. Although the low-level
verifier permits omitted or partial bindings for protocol compatibility, production task-key
disclosure must pass the complete map returned by `buildAllocationProofPayload(...)`.

## Authenticate the Service

Use your HTTP client to post the first map to `/api/v1/auth/challenges`. Pass the returned
`challenge_id` and `challenge` into the second builder, then post that map to
`/api/v1/auth/sessions`.

```java
import com.vgen.sdk.ServiceAuth;

var challengeBody = ServiceAuth.challengeRequest(credentials);

// Values returned by POST /api/v1/auth/challenges:
String challengeId = "ses_...";
String challenge = "...";

var sessionBody = ServiceAuth.sessionRequest(credentials, challengeId, challenge);
```

`sessionBody` contains the context-bound Ed25519 challenge signature. The private signing key
never leaves the application. Use the returned short-lived session token as a Bearer token.

## Sign a mutating request

VGen write operations also use a constrained RFC 9421 HTTP Message Signature. Sign the exact
UTF-8 request body and exact request target, including its raw query string:

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

Send the same `body` bytes that were signed. Re-serializing the object afterward can invalidate
the `Content-Digest` and signature.

## Encrypt a task payload

After the Gateway prepares a task, construct the canonical AAD from the IDs and key version in
the response. Encrypt the opaque workflow payload with a fresh task data key, wrap that key for
the assigned Worker, and wrap the same key directly for the Service's own X25519 key:

```java
import com.vgen.sdk.Aad;
import com.vgen.sdk.Base64Url;
import com.vgen.sdk.CanonicalJson;
import com.vgen.sdk.Hpke;
import com.vgen.sdk.PayloadCrypto;

import java.nio.charset.StandardCharsets;

byte[] taskAad = Aad.task(
    workspaceId,
    taskId,
    contentAttemptId,
    "payload",
    keyVersion
);
byte[] workerAad = Aad.task(
    workspaceId,
    taskId,
    assignedAttemptId,
    "payload",
    keyVersion
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

Use those three JSON strings as `encrypted_payload`, `worker_tdk_envelope`, and
`reader_envelope` in the commit body. The Gateway receives only ciphertext and envelopes. The
reader envelope is bound to this independent Service identity; never send the Service private key
or `taskDataKey` to the Gateway.

The matching decryption operations are:

```java
byte[] taskKey = Hpke.unwrapTaskKey(privateX25519Key, workerEnvelope, workerAad);
byte[] plaintext = PayloadCrypto.decrypt(taskKey, encryptedPayload, taskAad);

byte[] readerTaskKey = Hpke.unwrapTaskKey(
    credentials.deviceKeys().encryptionPrivateKey(), readerEnvelope, taskAad
);
```

`Hpke.wrapWorkspaceKey(...)`, `Hpke.unwrapWorkspaceKey(...)`, `Aad.workspaceKey(...)`, and
`PayloadCrypto.wrapTaskKeyForWorkspace(...)` remain available as low-level compatibility
primitives for existing protocol artifacts. This SDK does not currently provide Service
Workspace Data Key provisioning, and those primitives are not the public Service task-reader
flow.

## Security notes

- Store Service credentials in a secret manager with least-privilege access.
- Never log private keys, task keys, plaintext prompts, or session tokens.
- Generate a new task data key for every task.
- Treat an AAD mismatch or authentication-tag failure as a hard failure; do not retry with
  weakened validation.
- The deterministic private keys and nonces under `tests/sdk_compat/vectors.json` are public test
  fixtures and must never be used outside tests.

## Compatibility tests

```bash
cd sdks/java
mvn test
```

The tests read the repository-level Python-generated compatibility vectors directly. They cover
canonical JSON, Service credentials, key IDs, Challenge and HTTP signatures, task and Workspace
AAD, signed manifests, Worker ownership/allocation proofs, XChaCha20-Poly1305, RFC 9180 HPKE
task/Service-reader wraps, plus low-level Workspace compatibility primitives.
