package com.vgen.sdk;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Stable VGen identifiers derived from raw Ed25519 public keys. */
public final class KeyIds {
    private KeyIds() {}

    public static String device(byte[] signingPublicKey) {
        return derive("devkey_", "vgen-device-key-id-v1", signingPublicKey);
    }

    public static String root(byte[] signingPublicKey) {
        return derive("root_", "vgen-root-key-id-v1", signingPublicKey);
    }

    public static String rootSigningKeyId(byte[] signingPublicKey) {
        return root(signingPublicKey);
    }

    private static String derive(String prefix, String domain, byte[] signingPublicKey) {
        DeviceKeys.requireLength("Ed25519 public key", signingPublicKey, 32);
        byte[] input = PayloadCrypto.concat(
                domain.getBytes(StandardCharsets.US_ASCII),
                new byte[]{0},
                signingPublicKey);
        return prefix + Base64Url.encode(Arrays.copyOf(DeviceKeys.sha256(input), 20));
    }
}
