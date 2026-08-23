package com.vgen.sdk;

import java.util.LinkedHashMap;
import java.util.Map;

/** Request-body builders for the existing Service challenge/session flow. */
public final class ServiceAuth {
    private ServiceAuth() {}

    public static Map<String, Object> challengeRequest(ServiceCredentials credentials) {
        if (credentials == null) {
            throw new IllegalArgumentException("credentials are required");
        }
        return challengeRequest(credentials.serviceId());
    }

    public static Map<String, Object> challengeRequest(String serviceId) {
        if (serviceId == null || serviceId.isEmpty()) {
            throw new IllegalArgumentException("service_id is required");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("principal_type", "service");
        result.put("service_id", serviceId);
        return result;
    }

    public static Map<String, Object> sessionRequest(
            ServiceCredentials credentials, String challengeId, String challenge) {
        if (credentials == null) {
            throw new IllegalArgumentException("credentials are required");
        }
        if (challengeId == null || challengeId.isEmpty()) {
            throw new IllegalArgumentException("challenge_id is required");
        }
        if (challenge == null || challenge.isEmpty()) {
            throw new IllegalArgumentException("challenge is required");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("principal_type", "service");
        result.put("service_id", credentials.serviceId());
        result.put("challenge_id", challengeId);
        result.put("signature", credentials.deviceKeys().signChallenge(challenge));
        return result;
    }
}
