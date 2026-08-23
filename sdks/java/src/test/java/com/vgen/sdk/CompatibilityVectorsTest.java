package com.vgen.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Set;
import java.security.MessageDigest;
import java.util.Map;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class CompatibilityVectorsTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static JsonNode vectors;

    @TempDir
    Path temporaryDirectory;

    @BeforeAll
    static void loadVectors() throws Exception {
        Path workingDirectory = Path.of(System.getProperty("user.dir"));
        Path path = List.of(
                        workingDirectory.resolve("tests/sdk_compat/vectors.json"),
                        workingDirectory.resolve("../../tests/sdk_compat/vectors.json").normalize())
                .stream()
                .filter(Files::isRegularFile)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "tests/sdk_compat/vectors.json was not found from " + workingDirectory));
        vectors = MAPPER.readTree(Files.readAllBytes(path));
        assertEquals("vgen-sdk-compatibility-vectors", vectors.path("format").asText());
        assertEquals(1, vectors.path("version").asInt());
    }

    @Test
    void canonicalJsonMatchesPython() throws Exception {
        JsonNode expected = vectors.path("encoding").path("canonical_json");
        byte[] encoded = CanonicalJson.encode(expected.path("input"));
        assertEquals(expected.path("output_utf8").asText(), utf8(encoded));
        assertEquals(expected.path("output_hex").asText(), hex(encoded));
        assertEquals(expected.path("sha256").asText(), hex(MessageDigest.getInstance("SHA-256").digest(encoded)));
    }

    @Test
    void identityAndChallengeSignatureMatchPython() {
        JsonNode identity = vectors.path("identity");
        DeviceKeys keys = fixtureKeys();
        assertEquals(identity.path("signing_public_key").asText(), Base64Url.encode(keys.signingPublicKey()));
        assertEquals(identity.path("encryption_public_key").asText(), Base64Url.encode(keys.encryptionPublicKey()));
        assertEquals(identity.path("device_key_id").asText(), keys.keyId());
        assertEquals(identity.path("root_key_id_for_same_signing_key").asText(),
                KeyIds.root(keys.signingPublicKey()));
        assertEquals(identity.path("challenge_signature").asText(),
                keys.signChallenge(identity.path("challenge").asText()));
        assertThrows(IllegalArgumentException.class, () -> keys.signChallenge(""));
    }

    @Test
    void signedManifestAndWorkerCertificateMatchPython() {
        byte[] trustedRoot = decode(vectors.path("root_identity"), "signing_public_key");
        assertEquals(vectors.path("root_identity").path("root_key_id").asText(),
                VGenTrust.rootSigningKeyId(trustedRoot));

        Map<String, Object> signedManifest = objectMap(vectors.path("key_manifest").path("signed"));
        assertEquals(vectors.path("key_manifest").path("canonical_manifest_utf8").asText(),
                CanonicalJson.encodeToString(signedManifest.get("manifest")));
        org.junit.jupiter.api.Assertions.assertTrue(
                VGenTrust.verifyKeyManifest(signedManifest, trustedRoot));
        Map<String, Object> changedManifest = objectMap(vectors.path("key_manifest").path("signed"));
        objectMapValue(changedManifest, "manifest").put("key_version", 4);
        org.junit.jupiter.api.Assertions.assertFalse(
                VGenTrust.verifyKeyManifest(changedManifest, trustedRoot));

        JsonNode workerFixture = vectors.path("worker_owner_certificate");
        Map<String, Object> certificate = objectMap(workerFixture.path("certificate"));
        assertEquals(workerFixture.path("canonical_certificate_utf8").asText(),
                CanonicalJson.encodeToString(certificate));
        assertEquals(workerFixture.path("certificate_digest").asText(),
                VGenTrust.workerCertificateDigest(certificate));

        Map<String, Object> worker = objectMap(workerFixture.path("worker"));
        worker.put("certificate", certificate);
        worker.put("owner_root_signing_public_key", Base64Url.encode(trustedRoot));
        org.junit.jupiter.api.Assertions.assertTrue(VGenTrust.verifyWorkerOwnerCertificate(
                worker, trustedRoot, workerFixture.path("certificate").path("manifest")
                        .path("issued_at").asLong(), 300));
        worker.put("encryption_public_key", Base64Url.encode(new byte[32]));
        org.junit.jupiter.api.Assertions.assertFalse(VGenTrust.verifyWorkerOwnerCertificate(
                worker, trustedRoot, workerFixture.path("certificate").path("manifest")
                        .path("issued_at").asLong(), 300));
    }

    @Test
    void allocationProofPayloadAndVerificationMatchPython() {
        JsonNode fixture = vectors.path("workspace_allocation_proof");
        JsonNode inputs = fixture.path("inputs");
        Map<String, Object> certificate = objectMap(
                vectors.path("worker_owner_certificate").path("certificate"));
        Map<String, Object> expected = VGenTrust.buildAllocationProofPayload(
                inputs.path("allocation_id").asText(),
                inputs.path("workspace_id").asText(),
                inputs.path("pool_id").asText(),
                inputs.path("worker_id").asText(),
                inputs.path("worker_signing_public_key").asText(),
                inputs.path("worker_encryption_public_key").asText(),
                certificate,
                inputs.path("owner_consent_at").asDouble(),
                inputs.path("approver_root_key_id").asText(),
                inputs.path("issued_at").asLong());
        assertEquals(fixture.path("canonical_payload_utf8").asText(),
                CanonicalJson.encodeToString(expected));
        assertEquals(fixture.path("worker_certificate_digest").asText(),
                expected.get("worker_certificate_digest"));

        Map<String, Object> proof = objectMap(fixture.path("proof"));
        byte[] trustedRoot = decode(vectors.path("root_identity"), "signing_public_key");
        org.junit.jupiter.api.Assertions.assertTrue(VGenTrust.verifyAllocationProof(
                proof,
                trustedRoot,
                expected,
                inputs.path("issued_at").asLong(),
                300));
        Map<String, Object> changed = new java.util.LinkedHashMap<>(expected);
        changed.put("pool_id", "pol_zzzzzzzzzzzzzzzzzzzzzzzzzz");
        org.junit.jupiter.api.Assertions.assertFalse(VGenTrust.verifyAllocationProof(
                proof,
                trustedRoot,
                changed,
                inputs.path("issued_at").asLong(),
                300));
    }

    @Test
    void serviceCredentialFileRoundTripsByteForByte() {
        JsonNode expected = vectors.path("service_credentials");
        byte[] serialized = expected.path("serialized_utf8").asText().getBytes(StandardCharsets.UTF_8);
        ServiceCredentials credentials = ServiceCredentials.parse(serialized);
        assertArrayEquals(serialized, credentials.toJsonBytes());
        assertEquals(expected.path("value").path("service_id").asText(), credentials.serviceId());
        assertEquals(expected.path("value").path("workspace_id").asText(), credentials.workspaceId());
        assertEquals(expected.path("value").path("device_keys").path("key_id").asText(),
                credentials.deviceKeys().keyId());

        Map<String, Object> session = ServiceAuth.sessionRequest(
                credentials, "ses_sdk_compat", vectors.path("identity").path("challenge").asText());
        assertEquals("service", session.get("principal_type"));
        assertEquals(credentials.serviceId(), session.get("service_id"));
        assertEquals(vectors.path("identity").path("challenge_signature").asText(),
                session.get("signature"));

        String nonIntegerVersion = expected.path("serialized_utf8").asText()
                .replace("\"version\":1", "\"version\":1.5");
        assertThrows(IllegalArgumentException.class,
                () -> ServiceCredentials.parse(nonIntegerVersion));
    }

    @Test
    void privateCredentialLoaderRejectsLoosePermissionsAndSymlinks() throws Exception {
        byte[] serialized = vectors.path("service_credentials").path("serialized_utf8")
                .asText().getBytes(StandardCharsets.UTF_8);
        Path credentials = temporaryDirectory.resolve("service.json");
        Files.write(credentials, serialized);
        assumeTrue(Files.getFileAttributeView(credentials, PosixFileAttributeView.class) != null);
        Files.setPosixFilePermissions(credentials, Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
        assertEquals(vectors.path("service_credentials").path("value").path("service_id").asText(),
                ServiceCredentials.load(credentials).serviceId());

        Files.setPosixFilePermissions(credentials, Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ));
        assertThrows(IllegalArgumentException.class, () -> ServiceCredentials.load(credentials));

        Files.setPosixFilePermissions(credentials, Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
        Path link = temporaryDirectory.resolve("service-link.json");
        Files.createSymbolicLink(link, credentials.getFileName());
        assertThrows(IllegalArgumentException.class, () -> ServiceCredentials.load(link));
    }

    @Test
    void httpSignatureHeadersMatchPython() {
        JsonNode expected = vectors.path("http_signature");
        HttpSignatures.Headers signed = HttpSignatures.sign(
                fixtureKeys(),
                expected.path("method").asText(),
                expected.path("path").asText(),
                expected.path("body").asText().getBytes(StandardCharsets.UTF_8),
                expected.path("created").asLong(),
                expected.path("nonce").asText());
        assertEquals(expected.path("headers").path("Content-Digest").asText(), signed.contentDigest());
        assertEquals(expected.path("headers").path("Signature-Input").asText(), signed.signatureInput());
        assertEquals(expected.path("headers").path("Signature").asText(), signed.signature());
    }

    @Test
    void taskAndWorkspaceAadMatchPython() {
        JsonNode task = vectors.path("task_aad");
        JsonNode taskFields = task.path("fields");
        byte[] taskValue = Aad.task(
                taskFields.path("workspace_id").asText(),
                taskFields.path("task_id").asText(),
                taskFields.path("attempt_id").asText(),
                taskFields.path("artifact_id").asText(),
                taskFields.path("key_version").asInt());
        assertEquals(task.path("value_utf8").asText(), utf8(taskValue));

        JsonNode workspace = vectors.path("workspace_key_aad");
        JsonNode workspaceFields = workspace.path("fields");
        byte[] workspaceValue = Aad.workspaceKey(
                workspaceFields.path("workspace_id").asText(),
                workspaceFields.path("recipient_type").asText(),
                workspaceFields.path("recipient_id").asText(),
                workspaceFields.path("key_version").asInt(),
                workspaceFields.path("recipient_binding_digest").asText());
        assertEquals(workspace.path("value_utf8").asText(), utf8(workspaceValue));
    }

    @Test
    void xchachaPayloadMatchesLibsodium() {
        JsonNode expected = vectors.path("payload_xchacha20poly1305");
        byte[] key = decode(expected, "key");
        byte[] nonce = decode(expected, "nonce");
        byte[] aad = decode(expected, "aad");
        byte[] plaintext = decode(expected, "plaintext");
        PayloadCrypto.Ciphertext sealed = PayloadCrypto.encrypt(key, plaintext, aad, nonce);
        assertEquals(expected.path("ciphertext").asText(), Base64Url.encode(sealed.ciphertext()));
        assertArrayEquals(plaintext, PayloadCrypto.decrypt(key, sealed, aad));
        assertThrows(IllegalArgumentException.class,
                () -> PayloadCrypto.decrypt(key, sealed, "wrong".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void directHpkeMatchesPythonRfc9180Implementation() {
        JsonNode expected = vectors.path("hpke_direct");
        Hpke.Ciphertext sealed = Hpke.sealWithEphemeralPrivateKey(
                decode(expected, "recipient_public_key"),
                decode(expected, "plaintext"),
                decode(expected, "info"),
                decode(expected, "aad"),
                decode(expected, "sender_ephemeral_private_key"));
        assertEquals(expected.path("sealed").path("encapsulated_key").asText(),
                Base64Url.encode(sealed.encapsulatedKey()));
        assertEquals(expected.path("sealed").path("ciphertext").asText(),
                Base64Url.encode(sealed.ciphertext()));
        assertArrayEquals(decode(expected, "plaintext"), Hpke.open(
                decode(expected, "recipient_private_key"),
                hpkeCiphertext(expected.path("sealed")),
                decode(expected, "info"),
                decode(expected, "aad")));
    }

    @Test
    void taskAndWorkspaceKeyWrapsFromPythonOpenInJava() {
        JsonNode task = vectors.path("task_key_wrap");
        assertArrayEquals(decode(task, "task_data_key"), Hpke.unwrapTaskKey(
                decode(task, "recipient_private_key"),
                hpkeCiphertext(task.path("sealed")),
                decode(task, "aad")));
        assertThrows(IllegalArgumentException.class, () -> Hpke.unwrapTaskKey(
                decode(task, "recipient_private_key"),
                hpkeCiphertext(task.path("sealed")),
                "wrong".getBytes(StandardCharsets.UTF_8)));

        JsonNode workspace = vectors.path("workspace_key_wrap");
        assertArrayEquals(decode(workspace, "workspace_data_key"), Hpke.unwrapWorkspaceKey(
                decode(workspace, "recipient_private_key"),
                hpkeCiphertext(workspace.path("sealed")),
                decode(workspace, "aad")));
    }

    @Test
    void serviceReaderEnvelopeUsesTheIndependentServiceKey() {
        JsonNode expected = vectors.path("service_reader");
        ServiceCredentials service = ServiceCredentials.parse(
                vectors.path("service_credentials").path("serialized_utf8").asText());
        assertEquals(expected.path("service_id").asText(), service.serviceId());
        assertArrayEquals(decode(expected, "recipient_public_key"),
                service.deviceKeys().encryptionPublicKey());
        assertArrayEquals(decode(expected, "recipient_private_key"),
                service.deviceKeys().encryptionPrivateKey());

        Hpke.Ciphertext deterministic = Hpke.sealWithEphemeralPrivateKey(
                service.deviceKeys().encryptionPublicKey(),
                decode(expected, "task_data_key"),
                decode(expected, "effective_info"),
                decode(expected, "aad"),
                decode(expected, "sender_ephemeral_private_key"));
        assertEquals(expected.path("sealed").path("encapsulated_key").asText(),
                Base64Url.encode(deterministic.encapsulatedKey()));
        assertEquals(expected.path("sealed").path("ciphertext").asText(),
                Base64Url.encode(deterministic.ciphertext()));
        assertArrayEquals(decode(expected, "task_data_key"), Hpke.unwrapTaskKey(
                service.deviceKeys().encryptionPrivateKey(),
                hpkeCiphertext(expected.path("sealed")),
                decode(expected, "aad")));
    }

    @Test
    void lowLevelWorkspaceReaderPrimitiveMatchesPython() {
        JsonNode expected = vectors.path("workspace_reader");
        byte[] workspaceKey = decode(expected, "workspace_data_key");
        byte[] taskKey = decode(expected, "task_data_key");
        byte[] taskAad = decode(expected, "task_aad");
        PayloadCrypto.Ciphertext sealed = payloadCiphertext(expected.path("serialized"));
        assertArrayEquals(taskKey,
                PayloadCrypto.unwrapTaskKeyForWorkspace(workspaceKey, sealed, taskAad));

        PayloadCrypto.Ciphertext deterministic = PayloadCrypto.encrypt(
                workspaceKey,
                taskKey,
                decode(expected, "effective_aad"),
                decode(expected, "nonce"));
        assertEquals(expected.path("ciphertext").asText(), Base64Url.encode(deterministic.ciphertext()));
    }

    @Test
    void generatedKeysAndRandomEnvelopesRoundTrip() {
        DeviceKeys workerRecipient = DeviceKeys.generate();
        ServiceCredentials service = ServiceCredentials.parse(
                vectors.path("service_credentials").path("serialized_utf8").asText());
        byte[] taskAad = Aad.task(
                "wsp_aaaaaaaaaaaaaaaaaaaaaaaaaa",
                "tsk_bbbbbbbbbbbbbbbbbbbbbbbbbb",
                "atm_cccccccccccccccccccccccccc");
        byte[] taskKey = PayloadCrypto.generateKey();
        byte[] plaintext = "private task payload".getBytes(StandardCharsets.UTF_8);

        PayloadCrypto.Ciphertext payload = PayloadCrypto.encrypt(taskKey, plaintext, taskAad);
        Hpke.Ciphertext worker =
                Hpke.wrapTaskKey(workerRecipient.encryptionPublicKey(), taskKey, taskAad);
        Hpke.Ciphertext serviceReader = Hpke.wrapTaskKey(
                service.deviceKeys().encryptionPublicKey(), taskKey, taskAad);

        byte[] workerKey =
                Hpke.unwrapTaskKey(workerRecipient.encryptionPrivateKey(), worker, taskAad);
        byte[] readerKey = Hpke.unwrapTaskKey(
                service.deviceKeys().encryptionPrivateKey(), serviceReader, taskAad);
        assertArrayEquals(taskKey, workerKey);
        assertArrayEquals(taskKey, readerKey);
        assertArrayEquals(plaintext, PayloadCrypto.decrypt(workerKey, payload, taskAad));
    }

    private static DeviceKeys fixtureKeys() {
        JsonNode identity = vectors.path("identity");
        return new DeviceKeys(
                decode(identity, "signing_private_key"),
                decode(identity, "encryption_private_key"));
    }

    @SuppressWarnings("unchecked")
    private static Hpke.Ciphertext hpkeCiphertext(JsonNode value) {
        return Hpke.Ciphertext.fromMap(MAPPER.convertValue(value, Map.class));
    }

    @SuppressWarnings("unchecked")
    private static PayloadCrypto.Ciphertext payloadCiphertext(JsonNode value) {
        return PayloadCrypto.Ciphertext.fromMap(MAPPER.convertValue(value, Map.class));
    }

    private static byte[] decode(JsonNode value, String field) {
        return Base64Url.decode(value.path(field).asText());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> objectMap(JsonNode value) {
        return MAPPER.convertValue(value, Map.class);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> objectMapValue(Map<String, Object> value, String field) {
        return (Map<String, Object>) value.get(field);
    }

    private static String utf8(byte[] value) {
        return new String(value, StandardCharsets.UTF_8);
    }

    private static String hex(byte[] value) {
        return java.util.HexFormat.of().formatHex(value);
    }
}
