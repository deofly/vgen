package com.vgen.sdk;

import java.util.Base64;

/** Unpadded RFC 4648 base64url encoding used by VGen wire objects. */
public final class Base64Url {
    private Base64Url() {}

    public static String encode(byte[] value) {
        if (value == null) {
            throw new IllegalArgumentException("value is required");
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    public static byte[] decode(String value) {
        if (value == null) {
            throw new IllegalArgumentException("base64url value is required");
        }
        if (value.indexOf('=') >= 0 || !value.matches("[A-Za-z0-9_-]*")) {
            throw new IllegalArgumentException("invalid unpadded base64url value");
        }
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("invalid base64url value", exception);
        }
    }

    public static byte[] decode(String value, int expectedLength) {
        byte[] decoded = decode(value);
        if (decoded.length != expectedLength) {
            throw new IllegalArgumentException(
                    "decoded value must contain " + expectedLength + " bytes");
        }
        return decoded;
    }
}
