package com.vgen.sdk;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** libsodium-compatible XChaCha20-Poly1305-IETF payload encryption. */
public final class PayloadCrypto {
    public static final String ALGORITHM = "XChaCha20-Poly1305-IETF";
    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 24;
    private static final byte[] WORKSPACE_READER_AAD =
            "vgen-workspace-reader-envelope-v1".getBytes(StandardCharsets.US_ASCII);

    private PayloadCrypto() {}

    public record Ciphertext(byte[] nonce, byte[] ciphertext, String algorithm) {
        public Ciphertext {
            nonce = DeviceKeys.requireLength("payload nonce", nonce, NONCE_BYTES);
            if (ciphertext == null) {
                throw new IllegalArgumentException("payload ciphertext is required");
            }
            ciphertext = ciphertext.clone();
            if (!ALGORITHM.equals(algorithm)) {
                throw new IllegalArgumentException("unsupported payload encryption algorithm");
            }
        }

        public Ciphertext(byte[] nonce, byte[] ciphertext) {
            this(nonce, ciphertext, ALGORITHM);
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        public Map<String, String> toMap() {
            Map<String, String> value = new LinkedHashMap<>();
            value.put("algorithm", algorithm);
            value.put("nonce", Base64Url.encode(nonce));
            value.put("ciphertext", Base64Url.encode(ciphertext));
            return value;
        }

        public static Ciphertext fromMap(Map<String, ?> value) {
            if (value == null) {
                throw new IllegalArgumentException("payload ciphertext is required");
            }
            return new Ciphertext(
                    Base64Url.decode(required(value, "nonce"), NONCE_BYTES),
                    Base64Url.decode(required(value, "ciphertext")),
                    required(value, "algorithm"));
        }
    }

    public static byte[] generateKey() {
        byte[] key = new byte[KEY_BYTES];
        new SecureRandom().nextBytes(key);
        return key;
    }

    public static Ciphertext encrypt(byte[] key, byte[] plaintext, byte[] aad) {
        byte[] nonce = new byte[NONCE_BYTES];
        new SecureRandom().nextBytes(nonce);
        return encrypt(key, plaintext, aad, nonce);
    }

    static Ciphertext encrypt(byte[] key, byte[] plaintext, byte[] aad, byte[] nonce) {
        validateInputs(key, plaintext, aad);
        DeviceKeys.requireLength("payload nonce", nonce, NONCE_BYTES);
        return new Ciphertext(nonce, xchacha(true, key, nonce, plaintext, aad));
    }

    public static byte[] decrypt(byte[] key, Ciphertext sealed, byte[] aad) {
        if (sealed == null) {
            throw new IllegalArgumentException("payload ciphertext is required");
        }
        validateInputs(key, sealed.ciphertext, aad);
        return xchacha(false, key, sealed.nonce, sealed.ciphertext, aad);
    }

    public static Ciphertext wrapTaskKeyForWorkspace(
            byte[] workspaceDataKey, byte[] taskDataKey, byte[] aad) {
        DeviceKeys.requireLength("workspace data key", workspaceDataKey, KEY_BYTES);
        DeviceKeys.requireLength("task data key", taskDataKey, KEY_BYTES);
        return encrypt(workspaceDataKey, taskDataKey, concat(WORKSPACE_READER_AAD, new byte[]{0}, aad));
    }

    public static byte[] unwrapTaskKeyForWorkspace(
            byte[] workspaceDataKey, Ciphertext wrapped, byte[] aad) {
        DeviceKeys.requireLength("workspace data key", workspaceDataKey, KEY_BYTES);
        byte[] key = decrypt(workspaceDataKey, wrapped, concat(WORKSPACE_READER_AAD, new byte[]{0}, aad));
        return DeviceKeys.requireLength("unwrapped task data key", key, KEY_BYTES);
    }

    static byte[] xchacha(
            boolean encrypt, byte[] key, byte[] nonce, byte[] input, byte[] aad) {
        byte[] subkey = hChaCha20(key, Arrays.copyOfRange(nonce, 0, 16));
        byte[] ietfNonce = new byte[12];
        System.arraycopy(nonce, 16, ietfNonce, 4, 8);
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
        cipher.init(encrypt, new AEADParameters(new KeyParameter(subkey), 128, ietfNonce, aad));
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int length = cipher.processBytes(input, 0, input.length, output, 0);
        try {
            length += cipher.doFinal(output, length);
        } catch (InvalidCipherTextException exception) {
            throw new IllegalArgumentException("payload decryption failed", exception);
        } finally {
            Arrays.fill(subkey, (byte) 0);
        }
        return length == output.length ? output : Arrays.copyOf(output, length);
    }

    static byte[] hChaCha20(byte[] key, byte[] nonce) {
        DeviceKeys.requireLength("XChaCha20 key", key, 32);
        DeviceKeys.requireLength("HChaCha20 nonce", nonce, 16);
        int[] state = new int[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (int index = 0; index < 8; index++) {
            state[4 + index] = littleEndianInt(key, index * 4);
        }
        for (int index = 0; index < 4; index++) {
            state[12 + index] = littleEndianInt(nonce, index * 4);
        }
        for (int round = 0; round < 10; round++) {
            quarterRound(state, 0, 4, 8, 12);
            quarterRound(state, 1, 5, 9, 13);
            quarterRound(state, 2, 6, 10, 14);
            quarterRound(state, 3, 7, 11, 15);
            quarterRound(state, 0, 5, 10, 15);
            quarterRound(state, 1, 6, 11, 12);
            quarterRound(state, 2, 7, 8, 13);
            quarterRound(state, 3, 4, 9, 14);
        }
        byte[] result = new byte[32];
        int[] selected = {state[0], state[1], state[2], state[3],
                state[12], state[13], state[14], state[15]};
        for (int index = 0; index < selected.length; index++) {
            writeLittleEndianInt(selected[index], result, index * 4);
        }
        return result;
    }

    private static void quarterRound(int[] state, int a, int b, int c, int d) {
        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 16);
        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 12);
        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 8);
        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 7);
    }

    private static int littleEndianInt(byte[] input, int offset) {
        return (input[offset] & 0xff)
                | ((input[offset + 1] & 0xff) << 8)
                | ((input[offset + 2] & 0xff) << 16)
                | ((input[offset + 3] & 0xff) << 24);
    }

    private static void writeLittleEndianInt(int value, byte[] output, int offset) {
        output[offset] = (byte) value;
        output[offset + 1] = (byte) (value >>> 8);
        output[offset + 2] = (byte) (value >>> 16);
        output[offset + 3] = (byte) (value >>> 24);
    }

    private static void validateInputs(byte[] key, byte[] input, byte[] aad) {
        DeviceKeys.requireLength("payload key", key, KEY_BYTES);
        if (input == null) {
            throw new IllegalArgumentException("payload input is required");
        }
        if (aad == null) {
            throw new IllegalArgumentException("payload AAD is required");
        }
    }

    static byte[] concat(byte[]... values) {
        int length = 0;
        for (byte[] value : values) {
            if (value == null) {
                throw new IllegalArgumentException("byte value is required");
            }
            length += value.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }

    private static String required(Map<String, ?> value, String field) {
        Object item = value.get(field);
        if (!(item instanceof String text)) {
            throw new IllegalArgumentException(field + " is required");
        }
        return text;
    }
}
