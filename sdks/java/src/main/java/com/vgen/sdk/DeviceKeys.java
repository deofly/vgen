package com.vgen.sdk;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

/** Raw Ed25519/X25519 private seeds compatible with vgen-device-keys v1. */
public final class DeviceKeys {
    public static final String FORMAT = "vgen-device-keys";
    public static final int VERSION = 1;
    public static final byte[] MESSAGE_SIGNATURE_CONTEXT =
            "vgen-message-signature-v1".getBytes(StandardCharsets.US_ASCII);

    private final byte[] signingPrivateKey;
    private final byte[] encryptionPrivateKey;

    public DeviceKeys(byte[] signingPrivateKey, byte[] encryptionPrivateKey) {
        this.signingPrivateKey = requireLength("Ed25519 private key", signingPrivateKey, 32);
        this.encryptionPrivateKey = requireLength("X25519 private key", encryptionPrivateKey, 32);
    }

    public static DeviceKeys generate() {
        return generate(new SecureRandom());
    }

    public static DeviceKeys generate(SecureRandom random) {
        if (random == null) {
            throw new IllegalArgumentException("secure random is required");
        }
        return new DeviceKeys(
                new Ed25519PrivateKeyParameters(random).getEncoded(),
                new X25519PrivateKeyParameters(random).getEncoded());
    }

    public byte[] signingPrivateKey() {
        return signingPrivateKey.clone();
    }

    public byte[] encryptionPrivateKey() {
        return encryptionPrivateKey.clone();
    }

    public byte[] signingPublicKey() {
        return new Ed25519PrivateKeyParameters(signingPrivateKey, 0)
                .generatePublicKey().getEncoded();
    }

    public byte[] encryptionPublicKey() {
        return new X25519PrivateKeyParameters(encryptionPrivateKey, 0)
                .generatePublicKey().getEncoded();
    }

    public String keyId() {
        return KeyIds.device(signingPublicKey());
    }

    public byte[] signMessage(byte[] message) {
        return signMessage(message, MESSAGE_SIGNATURE_CONTEXT);
    }

    public byte[] signMessage(byte[] message, byte[] context) {
        if (message == null) {
            throw new IllegalArgumentException("message is required");
        }
        if (context == null || context.length == 0 || containsZero(context)) {
            throw new IllegalArgumentException("signature context must be non-empty and contain no NUL");
        }
        byte[] signed = new byte[context.length + 1 + message.length];
        System.arraycopy(context, 0, signed, 0, context.length);
        System.arraycopy(message, 0, signed, context.length + 1, message.length);
        return signRaw(signed);
    }

    public String signChallenge(String challenge) {
        if (challenge == null || challenge.isEmpty()) {
            throw new IllegalArgumentException("challenge is required");
        }
        return Base64Url.encode(signMessage(challenge.getBytes(StandardCharsets.UTF_8)));
    }

    byte[] signRaw(byte[] message) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, new Ed25519PrivateKeyParameters(signingPrivateKey, 0));
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    public Map<String, Object> toMap() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("format", FORMAT);
        value.put("version", VERSION);
        value.put("key_id", keyId());
        value.put("signing_private_key", Base64Url.encode(signingPrivateKey));
        value.put("encryption_private_key", Base64Url.encode(encryptionPrivateKey));
        return value;
    }

    public static DeviceKeys fromMap(Map<String, ?> value) {
        if (value == null
                || !FORMAT.equals(value.get("format"))
                || !isVersionOne(value.get("version"))) {
            throw new IllegalArgumentException("unsupported VGen device key format");
        }
        DeviceKeys keys = new DeviceKeys(
                Base64Url.decode(requiredString(value, "signing_private_key"), 32),
                Base64Url.decode(requiredString(value, "encryption_private_key"), 32));
        if (!MessageDigest.isEqual(
                keys.keyId().getBytes(StandardCharsets.US_ASCII),
                requiredString(value, "key_id").getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException("VGen device key ID mismatch");
        }
        return keys;
    }

    private static boolean isVersionOne(Object value) {
        if (value instanceof Byte || value instanceof Short
                || value instanceof Integer || value instanceof Long) {
            return ((Number) value).longValue() == VERSION;
        }
        return value instanceof BigInteger integer
                && integer.equals(BigInteger.valueOf(VERSION));
    }

    private static String requiredString(Map<String, ?> value, String key) {
        Object item = value.get(key);
        if (!(item instanceof String text) || text.isEmpty()) {
            throw new IllegalArgumentException(key + " is required");
        }
        return text;
    }

    static byte[] requireLength(String name, byte[] value, int length) {
        if (value == null || value.length != length) {
            throw new IllegalArgumentException(name + " must contain " + length + " bytes");
        }
        return value.clone();
    }

    static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static boolean containsZero(byte[] value) {
        for (byte item : value) {
            if (item == 0) {
                return true;
            }
        }
        return false;
    }
}
