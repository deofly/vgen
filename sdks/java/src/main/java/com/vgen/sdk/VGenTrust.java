package com.vgen.sdk;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Signature and binding verification for Gateway-provided key and Worker metadata. */
public final class VGenTrust {
    public static final String ALLOCATION_PROOF_KIND = "vgen-workspace-worker-allocation";
    public static final String WORKER_OWNER_CERTIFICATE_KIND = "vgen-worker-owner-certificate";
    private static final byte[] MANIFEST_CONTEXT = ascii("vgen-key-manifest-v1");
    private static final byte[] ALLOCATION_CONTEXT = ascii("vgen-workspace-allocation-proof-v1");

    private VGenTrust() {}

    public static String rootSigningKeyId(byte[] rootSigningPublicKey) {
        return KeyIds.rootSigningKeyId(rootSigningPublicKey);
    }

    /** Verify a generic root-signed VGen key manifest against a caller-trusted root key. */
    public static boolean verifyKeyManifest(
            Map<String, ?> signedManifest, byte[] trustedRootSigningPublicKey) {
        try {
            DeviceKeys.requireLength(
                    "trusted root signing public key", trustedRootSigningPublicKey, 32);
            Map<String, Object> signed = objectMap(signedManifest, "signed manifest");
            Map<String, Object> manifest = objectMap(signed.get("manifest"), "manifest");
            String signerKeyId = requiredString(signed, "signer_key_id");
            if (!signerKeyId.equals(rootSigningKeyId(trustedRootSigningPublicKey))) {
                return false;
            }
            byte[] signature = Base64Url.decode(requiredString(signed, "signature"), 64);
            return verifyContextSignature(
                    trustedRootSigningPublicKey,
                    CanonicalJson.encode(manifest),
                    signature,
                    MANIFEST_CONTEXT);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    /** Canonical SHA-256 digest used to bind an allocation to a Worker owner certificate. */
    public static String workerCertificateDigest(Object certificate) {
        Map<String, Object> value = objectMap(certificate, "Worker owner certificate");
        return "sha256:" + java.util.HexFormat.of().formatHex(
                DeviceKeys.sha256(CanonicalJson.encode(value)));
    }

    public static Map<String, Object> buildAllocationProofPayload(
            String allocationId,
            String workspaceId,
            String poolId,
            String workerId,
            String workerSigningPublicKey,
            String workerEncryptionPublicKey,
            Object workerCertificate,
            double ownerConsentAt,
            String approverRootKeyId) {
        return buildAllocationProofPayload(
                allocationId,
                workspaceId,
                poolId,
                workerId,
                workerSigningPublicKey,
                workerEncryptionPublicKey,
                workerCertificate,
                ownerConsentAt,
                approverRootKeyId,
                Instant.now().getEpochSecond());
    }

    /** Build the exact signed allocation statement used by the existing Gateway protocol. */
    public static Map<String, Object> buildAllocationProofPayload(
            String allocationId,
            String workspaceId,
            String poolId,
            String workerId,
            String workerSigningPublicKey,
            String workerEncryptionPublicKey,
            Object workerCertificate,
            double ownerConsentAt,
            String approverRootKeyId,
            long issuedAt) {
        if (!Double.isFinite(ownerConsentAt) || ownerConsentAt <= 0) {
            throw new IllegalArgumentException("allocation owner consent timestamp is required");
        }
        double rounded = Math.rint(ownerConsentAt * 1000.0d);
        if (!Double.isFinite(rounded) || rounded < 1 || rounded > Long.MAX_VALUE) {
            throw new IllegalArgumentException("allocation owner consent timestamp is out of range");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("version", 1);
        payload.put("kind", ALLOCATION_PROOF_KIND);
        payload.put("allocation_id", required("allocation_id", allocationId));
        payload.put("workspace_id", required("workspace_id", workspaceId));
        payload.put("pool_id", required("pool_id", poolId));
        payload.put("worker_id", required("worker_id", workerId));
        payload.put("worker_signing_public_key",
                required("worker_signing_public_key", workerSigningPublicKey));
        payload.put("worker_encryption_public_key",
                required("worker_encryption_public_key", workerEncryptionPublicKey));
        payload.put("worker_certificate_digest", workerCertificateDigest(workerCertificate));
        payload.put("owner_consent_at_ms", (long) rounded);
        payload.put("approver_root_key_id", required("approver_root_key_id", approverRootKeyId));
        payload.put("issued_at", issuedAt);
        return payload;
    }

    /** Low-level signature/schema verification; it does not bind a selected allocation. */
    public static boolean verifyAllocationProof(
            Map<String, ?> proof, byte[] trustedAdminRootSigningPublicKey) {
        return verifyAllocationProof(proof, trustedAdminRootSigningPublicKey, null);
    }

    /**
     * Verify an allocation proof against a trusted admin root and caller-built expected bindings.
     * Production callers should pass the complete map produced with
     * {@link #buildAllocationProofPayload} from the Workspace, Pool, Worker, certificate and
     * consent metadata selected by the application.
     */
    public static boolean verifyAllocationProof(
            Map<String, ?> proof,
            byte[] trustedAdminRootSigningPublicKey,
            Map<String, ?> expected) {
        return verifyAllocationProof(
                proof,
                trustedAdminRootSigningPublicKey,
                expected,
                Instant.now().getEpochSecond(),
                300);
    }

    public static boolean verifyAllocationProof(
            Map<String, ?> proof,
            byte[] trustedAdminRootSigningPublicKey,
            Map<String, ?> expected,
            long now,
            long maxFutureSeconds) {
        if (maxFutureSeconds < 0) {
            return false;
        }
        try {
            DeviceKeys.requireLength(
                    "trusted admin root signing public key",
                    trustedAdminRootSigningPublicKey,
                    32);
            Map<String, Object> signed = objectMap(proof, "allocation proof");
            Map<String, Object> payload = objectMap(signed.get("payload"), "allocation payload");
            String signerKeyId = requiredString(signed, "signer_key_id");
            long issuedAt = integer(payload.get("issued_at"), "issued_at");
            long ownerConsentAtMs = integer(
                    payload.get("owner_consent_at_ms"), "owner_consent_at_ms");
            String certificateDigest = requiredString(payload, "worker_certificate_digest");
            boolean schemaValid = integer(payload.get("version"), "version") == 1
                    && ALLOCATION_PROOF_KIND.equals(payload.get("kind"))
                    && hasText(payload, "allocation_id")
                    && hasText(payload, "workspace_id")
                    && hasText(payload, "pool_id")
                    && hasText(payload, "worker_id")
                    && hasText(payload, "worker_signing_public_key")
                    && hasText(payload, "worker_encryption_public_key")
                    && certificateDigest.matches("sha256:[0-9a-f]{64}")
                    && ownerConsentAtMs > 0
                    && signerKeyId.equals(payload.get("approver_root_key_id"))
                    && signerKeyId.equals(rootSigningKeyId(trustedAdminRootSigningPublicKey));
            if (!schemaValid || issuedAt > now + maxFutureSeconds) {
                return false;
            }
            Map<String, ?> bindings = expected == null ? Map.of() : expected;
            for (Map.Entry<String, ?> binding : bindings.entrySet()) {
                if (!semanticallyEqual(payload.get(binding.getKey()), binding.getValue())) {
                    return false;
                }
            }
            byte[] signature = Base64Url.decode(requiredString(signed, "signature"), 64);
            return verifyContextSignature(
                    trustedAdminRootSigningPublicKey,
                    CanonicalJson.encode(payload),
                    signature,
                    ALLOCATION_CONTEXT);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    /**
     * Verify that a caller-trusted owner root signed the certificate and bound the exact Worker
     * signing and encryption keys in the supplied Gateway Worker map.
     */
    public static boolean verifyWorkerOwnerCertificate(
            Map<String, ?> worker, byte[] trustedOwnerRootSigningPublicKey) {
        return verifyWorkerOwnerCertificate(
                worker, trustedOwnerRootSigningPublicKey, Instant.now().getEpochSecond(), 300);
    }

    public static boolean verifyWorkerOwnerCertificate(
            Map<String, ?> worker,
            byte[] trustedOwnerRootSigningPublicKey,
            long now,
            long maxFutureSeconds) {
        if (worker == null || maxFutureSeconds < 0) {
            return false;
        }
        try {
            DeviceKeys.requireLength(
                    "trusted owner root signing public key", trustedOwnerRootSigningPublicKey, 32);
            Map<String, Object> certificate = objectMap(
                    worker.get("certificate"), "Worker owner certificate");
            if (!verifyKeyManifest(certificate, trustedOwnerRootSigningPublicKey)) {
                return false;
            }
            Map<String, Object> manifest = objectMap(
                    certificate.get("manifest"), "Worker owner certificate manifest");
            String signingPublicKey = requiredString(worker, "signing_public_key");
            String encryptionPublicKey = requiredString(worker, "encryption_public_key");
            byte[] signingBytes = Base64Url.decode(signingPublicKey, 32);
            Base64Url.decode(encryptionPublicKey, 32);
            String signerKeyId = requiredString(certificate, "signer_key_id");
            long issuedAt = integer(manifest.get("issued_at"), "issued_at");
            if (issuedAt > now + maxFutureSeconds
                    || integer(manifest.get("version"), "version") != 1
                    || !WORKER_OWNER_CERTIFICATE_KIND.equals(manifest.get("kind"))
                    || !signerKeyId.equals(manifest.get("owner_root_key_id"))
                    || !KeyIds.device(signingBytes).equals(manifest.get("worker_key_id"))
                    || !signingPublicKey.equals(manifest.get("worker_signing_public_key"))
                    || !encryptionPublicKey.equals(manifest.get("worker_encryption_public_key"))) {
                return false;
            }
            Object presentedRoot = worker.get("owner_root_signing_public_key");
            return presentedRoot == null
                    || Base64Url.encode(trustedOwnerRootSigningPublicKey)
                    .equals(String.valueOf(presentedRoot));
        } catch (RuntimeException exception) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> objectMap(Object value, String name) {
        if (value instanceof String text) {
            try {
                JsonNode node = CanonicalJson.mapper().readTree(text);
                if (node == null || !node.isObject()) {
                    throw new IllegalArgumentException(name + " must be a JSON object");
                }
                return CanonicalJson.mapper().convertValue(node, Map.class);
            } catch (JsonProcessingException exception) {
                throw new IllegalArgumentException(name + " is not valid JSON", exception);
            }
        }
        if (!(value instanceof Map<?, ?> source)) {
            throw new IllegalArgumentException(name + " must be a JSON object");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> item : source.entrySet()) {
            if (!(item.getKey() instanceof String key)) {
                throw new IllegalArgumentException(name + " field names must be strings");
            }
            result.put(key, item.getValue());
        }
        return result;
    }

    private static boolean verifyContextSignature(
            byte[] publicKey, byte[] message, byte[] signature, byte[] context) {
        byte[] signed = PayloadCrypto.concat(context, new byte[]{0}, message);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        verifier.update(signed, 0, signed.length);
        return verifier.verifySignature(signature);
    }

    private static boolean hasText(Map<String, ?> value, String field) {
        Object item = value.get(field);
        return item instanceof String text && !text.isEmpty();
    }

    private static String requiredString(Map<String, ?> value, String field) {
        Object item = value.get(field);
        if (!(item instanceof String text) || text.isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return text;
    }

    private static long integer(Object value, String field) {
        if (!(value instanceof Number number)
                || value instanceof Float
                || value instanceof Double) {
            throw new IllegalArgumentException(field + " must be an integer");
        }
        if (number instanceof BigDecimal decimal) {
            try {
                return decimal.longValueExact();
            } catch (ArithmeticException exception) {
                throw new IllegalArgumentException(field + " is out of range", exception);
            }
        }
        return number.longValue();
    }

    private static boolean semanticallyEqual(Object left, Object right) {
        if (left instanceof Number leftNumber && right instanceof Number rightNumber) {
            try {
                return new BigDecimal(leftNumber.toString())
                        .compareTo(new BigDecimal(rightNumber.toString())) == 0;
            } catch (NumberFormatException exception) {
                return false;
            }
        }
        return Objects.equals(left, right);
    }

    private static String required(String field, String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
