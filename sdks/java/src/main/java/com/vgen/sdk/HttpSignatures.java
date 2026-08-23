package com.vgen.sdk;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** VGen's constrained RFC 9421 Ed25519 HTTP Message Signature profile. */
public final class HttpSignatures {
    public static final String SIGNATURE_LABEL = "sig1";
    private static final String COMPONENTS = "(\"@method\" \"@path\" \"content-digest\")";

    private HttpSignatures() {}

    public record Headers(String contentDigest, String signatureInput, String signature) {
        public Map<String, String> toMap() {
            Map<String, String> result = new LinkedHashMap<>();
            result.put("Content-Digest", contentDigest);
            result.put("Signature-Input", signatureInput);
            result.put("Signature", signature);
            return result;
        }
    }

    public static Headers sign(DeviceKeys keys, String method, String path, byte[] body) {
        byte[] nonce = new byte[24];
        new SecureRandom().nextBytes(nonce);
        return sign(keys, method, path, body, Instant.now().getEpochSecond(), Base64Url.encode(nonce));
    }

    public static Headers sign(
            DeviceKeys keys,
            String method,
            String path,
            byte[] body,
            long created,
            String nonce) {
        if (keys == null) {
            throw new IllegalArgumentException("keys are required");
        }
        if (body == null) {
            throw new IllegalArgumentException("HTTP body must be bytes");
        }
        String normalizedMethod = validateMethod(method);
        String normalizedPath = validatePath(path);
        if (created < 0 || created > 999_999_999_999L) {
            throw new IllegalArgumentException("HTTP signature created time is out of range");
        }
        if (nonce == null || !nonce.matches("[A-Za-z0-9_-]{16,128}")) {
            throw new IllegalArgumentException("HTTP signature nonce is not canonical base64url");
        }
        String keyId = keys.keyId();
        if (!keyId.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw new IllegalArgumentException("HTTP signature key_id contains unsupported characters");
        }
        String digest = "sha-256=:" + Base64.getEncoder().encodeToString(DeviceKeys.sha256(body)) + ":";
        String params = COMPONENTS + ";created=" + created + ";nonce=\"" + nonce
                + "\";keyid=\"" + keyId + "\";alg=\"ed25519\"";
        String base = "\"@method\": " + normalizedMethod + "\n"
                + "\"@path\": " + normalizedPath + "\n"
                + "\"content-digest\": " + digest + "\n"
                + "\"@signature-params\": " + params;
        String signature = Base64.getEncoder().encodeToString(
                keys.signRaw(base.getBytes(StandardCharsets.UTF_8)));
        return new Headers(
                digest,
                SIGNATURE_LABEL + "=" + params,
                SIGNATURE_LABEL + "=:" + signature + ":");
    }

    private static String validateMethod(String method) {
        if (method == null) {
            throw new IllegalArgumentException("HTTP method is required");
        }
        String value = method.toUpperCase(Locale.ROOT);
        if (!value.matches("[A-Z]+")) {
            throw new IllegalArgumentException("HTTP method is invalid");
        }
        return value;
    }

    private static String validatePath(String path) {
        if (path == null || !path.startsWith("/") || path.indexOf('#') >= 0) {
            throw new IllegalArgumentException(
                    "HTTP path must be an ASCII absolute request target with percent encoding");
        }
        for (int index = 0; index < path.length(); index++) {
            char character = path.charAt(index);
            if (character < 0x21 || character > 0x7e) {
                throw new IllegalArgumentException(
                        "HTTP path must be an ASCII absolute request target with percent encoding");
            }
        }
        return path;
    }
}
