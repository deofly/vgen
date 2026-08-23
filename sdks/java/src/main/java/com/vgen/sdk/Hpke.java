package com.vgen.sdk;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** RFC 9180 Base-mode X25519/HKDF-SHA256/ChaCha20-Poly1305 key envelopes. */
public final class Hpke {
    public static final String ALGORITHM = "HPKE-Base-X25519-HKDF-SHA256-ChaCha20Poly1305";
    private static final byte[] VERSION = ascii("HPKE-v1");
    private static final byte[] KEM_SUITE_ID = concat(ascii("KEM"), i2osp(0x0020));
    private static final byte[] HPKE_SUITE_ID = concat(
            ascii("HPKE"), i2osp(0x0020), i2osp(0x0001), i2osp(0x0003));
    private static final byte[] TASK_WRAP_INFO = ascii("vgen-task-key-wrap-v1");
    private static final byte[] WORKSPACE_WRAP_INFO = ascii("vgen-workspace-key-wrap-v1");
    private static final int HASH_BYTES = 32;
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;

    private Hpke() {}

    public record Ciphertext(byte[] encapsulatedKey, byte[] ciphertext, String algorithm) {
        public Ciphertext {
            encapsulatedKey = DeviceKeys.requireLength(
                    "HPKE encapsulated key", encapsulatedKey, 32);
            if (ciphertext == null) {
                throw new IllegalArgumentException("HPKE ciphertext is required");
            }
            ciphertext = ciphertext.clone();
            if (!ALGORITHM.equals(algorithm)) {
                throw new IllegalArgumentException("unsupported HPKE algorithm");
            }
        }

        public Ciphertext(byte[] encapsulatedKey, byte[] ciphertext) {
            this(encapsulatedKey, ciphertext, ALGORITHM);
        }

        @Override
        public byte[] encapsulatedKey() {
            return encapsulatedKey.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        public Map<String, String> toMap() {
            Map<String, String> value = new LinkedHashMap<>();
            value.put("algorithm", algorithm);
            value.put("encapsulated_key", Base64Url.encode(encapsulatedKey));
            value.put("ciphertext", Base64Url.encode(ciphertext));
            return value;
        }

        public static Ciphertext fromMap(Map<String, ?> value) {
            if (value == null) {
                throw new IllegalArgumentException("HPKE ciphertext is required");
            }
            return new Ciphertext(
                    Base64Url.decode(required(value, "encapsulated_key"), 32),
                    Base64Url.decode(required(value, "ciphertext")),
                    required(value, "algorithm"));
        }
    }

    public static Ciphertext seal(
            byte[] recipientPublicKey, byte[] plaintext, byte[] info, byte[] aad) {
        return seal(recipientPublicKey, plaintext, info, aad, new SecureRandom());
    }

    static Ciphertext seal(
            byte[] recipientPublicKey,
            byte[] plaintext,
            byte[] info,
            byte[] aad,
            SecureRandom random) {
        DeviceKeys.requireLength("recipient public key", recipientPublicKey, 32);
        require("plaintext", plaintext);
        require("HPKE info", info);
        require("HPKE AAD", aad);
        X25519PrivateKeyParameters ephemeral = new X25519PrivateKeyParameters(random);
        return sealWithEphemeral(recipientPublicKey, plaintext, info, aad, ephemeral);
    }

    static Ciphertext sealWithEphemeralPrivateKey(
            byte[] recipientPublicKey,
            byte[] plaintext,
            byte[] info,
            byte[] aad,
            byte[] ephemeralPrivateKey) {
        DeviceKeys.requireLength("ephemeral private key", ephemeralPrivateKey, 32);
        DeviceKeys.requireLength("recipient public key", recipientPublicKey, 32);
        require("plaintext", plaintext);
        require("HPKE info", info);
        require("HPKE AAD", aad);
        return sealWithEphemeral(
                recipientPublicKey,
                plaintext,
                info,
                aad,
                new X25519PrivateKeyParameters(ephemeralPrivateKey, 0));
    }

    private static Ciphertext sealWithEphemeral(
            byte[] recipientPublicKey,
            byte[] plaintext,
            byte[] info,
            byte[] aad,
            X25519PrivateKeyParameters ephemeral) {
        byte[] encapsulated = ephemeral.generatePublicKey().getEncoded();
        byte[] sharedSecret = extractAndExpand(
                rawDh(ephemeral, recipientPublicKey),
                concat(encapsulated, recipientPublicKey));
        KeySchedule schedule = keySchedule(sharedSecret, info);
        return new Ciphertext(
                encapsulated,
                aead(true, schedule.key, schedule.baseNonce, plaintext, aad));
    }

    public static byte[] open(
            byte[] recipientPrivateKey, Ciphertext sealed, byte[] info, byte[] aad) {
        DeviceKeys.requireLength("recipient private key", recipientPrivateKey, 32);
        if (sealed == null) {
            throw new IllegalArgumentException("HPKE ciphertext is required");
        }
        require("HPKE info", info);
        require("HPKE AAD", aad);
        X25519PrivateKeyParameters recipient = new X25519PrivateKeyParameters(recipientPrivateKey, 0);
        byte[] recipientPublicKey = recipient.generatePublicKey().getEncoded();
        byte[] sharedSecret = extractAndExpand(
                rawDh(recipient, sealed.encapsulatedKey),
                concat(sealed.encapsulatedKey, recipientPublicKey));
        KeySchedule schedule = keySchedule(sharedSecret, info);
        return aead(false, schedule.key, schedule.baseNonce, sealed.ciphertext, aad);
    }

    public static Ciphertext wrapTaskKey(
            byte[] recipientPublicKey, byte[] taskDataKey, byte[] aad) {
        DeviceKeys.requireLength("task data key", taskDataKey, 32);
        return seal(
                recipientPublicKey,
                taskDataKey,
                concat(TASK_WRAP_INFO, new byte[]{0}, DeviceKeys.sha256(aad)),
                aad);
    }

    public static byte[] unwrapTaskKey(
            byte[] recipientPrivateKey, Ciphertext wrapped, byte[] aad) {
        byte[] result = open(
                recipientPrivateKey,
                wrapped,
                concat(TASK_WRAP_INFO, new byte[]{0}, DeviceKeys.sha256(aad)),
                aad);
        return DeviceKeys.requireLength("unwrapped task data key", result, 32);
    }

    public static Ciphertext wrapWorkspaceKey(
            byte[] recipientPublicKey, byte[] workspaceDataKey, byte[] aad) {
        DeviceKeys.requireLength("workspace data key", workspaceDataKey, 32);
        return seal(
                recipientPublicKey,
                workspaceDataKey,
                concat(WORKSPACE_WRAP_INFO, new byte[]{0}, DeviceKeys.sha256(aad)),
                aad);
    }

    public static byte[] unwrapWorkspaceKey(
            byte[] recipientPrivateKey, Ciphertext wrapped, byte[] aad) {
        byte[] result = open(
                recipientPrivateKey,
                wrapped,
                concat(WORKSPACE_WRAP_INFO, new byte[]{0}, DeviceKeys.sha256(aad)),
                aad);
        return DeviceKeys.requireLength("workspace data key", result, 32);
    }

    private static byte[] rawDh(X25519PrivateKeyParameters privateKey, byte[] publicKey) {
        byte[] dh = new byte[32];
        try {
            privateKey.generateSecret(new X25519PublicKeyParameters(publicKey, 0), dh, 0);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("invalid X25519 public key", exception);
        }
        return dh;
    }

    private static byte[] extractAndExpand(byte[] dh, byte[] kemContext) {
        byte[] eaePrk = labeledExtract(new byte[0], KEM_SUITE_ID, ascii("eae_prk"), dh);
        return labeledExpand(
                eaePrk, KEM_SUITE_ID, ascii("shared_secret"), kemContext, HASH_BYTES);
    }

    private static KeySchedule keySchedule(byte[] sharedSecret, byte[] info) {
        byte[] pskIdHash = labeledExtract(
                new byte[0], HPKE_SUITE_ID, ascii("psk_id_hash"), new byte[0]);
        byte[] infoHash = labeledExtract(new byte[0], HPKE_SUITE_ID, ascii("info_hash"), info);
        byte[] context = concat(new byte[]{0}, pskIdHash, infoHash);
        byte[] secret = labeledExtract(
                sharedSecret, HPKE_SUITE_ID, ascii("secret"), new byte[0]);
        byte[] key = labeledExpand(secret, HPKE_SUITE_ID, ascii("key"), context, KEY_BYTES);
        byte[] nonce = labeledExpand(
                secret, HPKE_SUITE_ID, ascii("base_nonce"), context, NONCE_BYTES);
        return new KeySchedule(key, nonce);
    }

    private static byte[] labeledExtract(
            byte[] salt, byte[] suiteId, byte[] label, byte[] ikm) {
        return hmac(salt, concat(VERSION, suiteId, label, ikm));
    }

    private static byte[] labeledExpand(
            byte[] prk,
            byte[] suiteId,
            byte[] label,
            byte[] info,
            int length) {
        if (length < 0 || length > 0xffff) {
            throw new IllegalArgumentException("HPKE output length is out of range");
        }
        return hkdfExpand(
                prk,
                concat(i2osp(length), VERSION, suiteId, label, info),
                length);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        if (length > 255 * HASH_BYTES) {
            throw new IllegalArgumentException("HKDF output length is out of range");
        }
        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        for (int counter = 1; offset < length; counter++) {
            previous = hmac(prk, concat(previous, info, new byte[]{(byte) counter}));
            int count = Math.min(previous.length, length - offset);
            System.arraycopy(previous, 0, output, offset, count);
            offset += count;
        }
        return output;
    }

    private static byte[] hmac(byte[] key, byte[] value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] resolvedKey = key.length == 0 ? new byte[HASH_BYTES] : key;
            mac.init(new SecretKeySpec(resolvedKey, "HmacSHA256"));
            return mac.doFinal(value);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HmacSHA256 is unavailable", exception);
        }
    }

    private static byte[] aead(
            boolean encrypt, byte[] key, byte[] nonce, byte[] input, byte[] aad) {
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
        cipher.init(encrypt, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int length = cipher.processBytes(input, 0, input.length, output, 0);
        try {
            length += cipher.doFinal(output, length);
        } catch (InvalidCipherTextException exception) {
            throw new IllegalArgumentException("HPKE decryption failed", exception);
        }
        return length == output.length ? output : Arrays.copyOf(output, length);
    }

    private static byte[] i2osp(int value) {
        return new byte[]{(byte) (value >>> 8), (byte) value};
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[]... values) {
        return PayloadCrypto.concat(values);
    }

    private static void require(String name, byte[] value) {
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
    }

    private static String required(Map<String, ?> value, String field) {
        Object item = value.get(field);
        if (!(item instanceof String text)) {
            throw new IllegalArgumentException(field + " is required");
        }
        return text;
    }

    private record KeySchedule(byte[] key, byte[] baseNonce) {}
}
