package com.vgen.sdk;

import java.util.LinkedHashMap;
import java.util.Map;

/** Canonical additional-authenticated-data builders used by task and Workspace envelopes. */
public final class Aad {
    private Aad() {}

    public static byte[] task(
            String workspaceId,
            String taskId,
            String attemptId) {
        return task(workspaceId, taskId, attemptId, "payload", 1);
    }

    public static byte[] task(
            String workspaceId,
            String taskId,
            String attemptId,
            String artifactId,
            int keyVersion) {
        if (keyVersion < 1) {
            throw new IllegalArgumentException("key_version must be positive");
        }
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("protocol_version", "v1");
        value.put("workspace_id", required("workspace_id", workspaceId));
        value.put("task_id", required("task_id", taskId));
        value.put("attempt_id", required("attempt_id", attemptId));
        value.put("artifact_id", required("artifact_id", artifactId));
        value.put("key_version", keyVersion);
        return CanonicalJson.encode(value);
    }

    public static byte[] workspaceKey(
            String workspaceId,
            String recipientType,
            String recipientId,
            int keyVersion) {
        return workspaceKey(workspaceId, recipientType, recipientId, keyVersion, null);
    }

    public static byte[] workspaceKey(
            String workspaceId,
            String recipientType,
            String recipientId,
            int keyVersion,
            String recipientBindingDigest) {
        if (keyVersion < 1) {
            throw new IllegalArgumentException("key_version must be positive");
        }
        if (recipientBindingDigest != null && !recipientBindingDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("recipient binding digest must be lowercase SHA-256");
        }
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("protocol_version", recipientBindingDigest == null ? "v1" : "v2");
        value.put("workspace_id", required("workspace_id", workspaceId));
        value.put("recipient_type", required("recipient_type", recipientType));
        value.put("recipient_id", required("recipient_id", recipientId));
        value.put("key_version", keyVersion);
        if (recipientBindingDigest != null) {
            value.put("recipient_binding_digest", recipientBindingDigest);
        }
        return CanonicalJson.encode(value);
    }

    private static String required(String name, String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
