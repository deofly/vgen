package com.vgen.sdk;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

/** Parser and serializer for the existing vgen-service-credentials v1 file. */
public final class ServiceCredentials {
    public static final String FORMAT = "vgen-service-credentials";
    public static final int VERSION = 1;

    private static final ObjectMapper CREDENTIAL_MAPPER = JsonMapper.builder()
            .enable(JsonWriteFeature.ESCAPE_NON_ASCII)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .build();

    private final String serviceId;
    private final String workspaceId;
    private final String name;
    private final List<String> scopes;
    private final String enrollmentId;
    private final DeviceKeys deviceKeys;

    public ServiceCredentials(
            String serviceId,
            String workspaceId,
            String name,
            List<String> scopes,
            String enrollmentId,
            DeviceKeys deviceKeys) {
        this.serviceId = required("service_id", serviceId);
        this.workspaceId = required("workspace_id", workspaceId);
        this.name = required("name", name);
        this.enrollmentId = required("enrollment_id", enrollmentId);
        if (scopes == null || scopes.isEmpty() || scopes.stream().anyMatch(item -> item == null || item.isEmpty())) {
            throw new IllegalArgumentException("Service scopes are required");
        }
        this.scopes = List.copyOf(scopes);
        if (deviceKeys == null) {
            throw new IllegalArgumentException("device_keys are required");
        }
        this.deviceKeys = deviceKeys;
    }

    public static ServiceCredentials generate(
            String serviceId,
            String workspaceId,
            String name,
            List<String> scopes,
            String enrollmentId) {
        List<String> normalized = new ArrayList<>(new LinkedHashSet<>(scopes));
        normalized.sort(String::compareTo);
        return new ServiceCredentials(
                serviceId, workspaceId, name, normalized, enrollmentId, DeviceKeys.generate());
    }

    public String serviceId() {
        return serviceId;
    }

    public String workspaceId() {
        return workspaceId;
    }

    public String name() {
        return name;
    }

    public List<String> scopes() {
        return scopes;
    }

    public String enrollmentId() {
        return enrollmentId;
    }

    public DeviceKeys deviceKeys() {
        return deviceKeys;
    }

    public Map<String, Object> publicInfo() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("service_id", serviceId);
        result.put("workspace_id", workspaceId);
        result.put("name", name);
        result.put("scopes", scopes);
        result.put("enrollment_id", enrollmentId);
        result.put("key_id", deviceKeys.keyId());
        result.put("signing_public_key", Base64Url.encode(deviceKeys.signingPublicKey()));
        result.put("encryption_public_key", Base64Url.encode(deviceKeys.encryptionPublicKey()));
        return result;
    }

    public byte[] toJsonBytes() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("format", FORMAT);
        value.put("version", VERSION);
        value.put("service_id", serviceId);
        value.put("workspace_id", workspaceId);
        value.put("name", name);
        value.put("scopes", scopes);
        value.put("enrollment_id", enrollmentId);
        value.put("device_keys", deviceKeys.toMap());
        try {
            return (CREDENTIAL_MAPPER.writeValueAsString(value) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Service credentials cannot be serialized", exception);
        }
    }

    public String toJson() {
        return new String(toJsonBytes(), StandardCharsets.UTF_8);
    }

    public static ServiceCredentials parse(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Service credential data are required");
        }
        return parse(value.getBytes(StandardCharsets.UTF_8));
    }

    /** Load an owner-only credential file without following symbolic links. */
    public static ServiceCredentials load(Path path) throws IOException {
        if (path == null) {
            throw new IllegalArgumentException("Service credential path is required");
        }
        BasicFileAttributes basic = Files.readAttributes(
                path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (basic.isSymbolicLink()) {
            throw new IllegalArgumentException("Private Service files must not be symbolic links");
        }
        if (!basic.isRegularFile()) {
            throw new IllegalArgumentException("Service credential path must be a regular file");
        }
        PosixFileAttributeView posix = Files.getFileAttributeView(
                path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            PosixFileAttributes attributes = posix.readAttributes();
            Set<PosixFilePermission> expected = Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            if (!attributes.permissions().equals(expected)) {
                throw new IllegalArgumentException("Service credential file must have mode 0600");
            }
        }
        if (basic.size() > 1_048_576) {
            throw new IllegalArgumentException("Service credential file is too large");
        }
        Set<OpenOption> options = new HashSet<>();
        options.add(StandardOpenOption.READ);
        options.add(LinkOption.NOFOLLOW_LINKS);
        try (SeekableByteChannel channel = Files.newByteChannel(path, options);
             ByteArrayOutputStream output = new ByteArrayOutputStream((int) basic.size())) {
            ByteBuffer buffer = ByteBuffer.allocate(8192);
            int total = 0;
            while (channel.read(buffer) >= 0) {
                if (buffer.position() == 0) {
                    continue;
                }
                total += buffer.position();
                if (total > 1_048_576) {
                    throw new IllegalArgumentException("Service credential file is too large");
                }
                output.write(buffer.array(), 0, buffer.position());
                buffer.clear();
            }
            return parse(output.toByteArray());
        }
    }

    @SuppressWarnings("unchecked")
    public static ServiceCredentials parse(byte[] value) {
        try {
            JsonNode raw = CanonicalJson.mapper().readTree(value);
            if (raw == null || !raw.isObject()
                    || !FORMAT.equals(raw.path("format").asText())
                    || !raw.path("version").isIntegralNumber()
                    || !raw.path("version").canConvertToInt()
                    || raw.path("version").intValue() != VERSION) {
                throw new IllegalArgumentException("Unsupported Service credential format");
            }
            List<String> scopes = new ArrayList<>();
            JsonNode rawScopes = raw.get("scopes");
            if (rawScopes == null || !rawScopes.isArray()) {
                throw new IllegalArgumentException("Service credential scopes are invalid");
            }
            for (JsonNode scope : rawScopes) {
                if (!scope.isTextual()) {
                    throw new IllegalArgumentException("Service credential scopes are invalid");
                }
                scopes.add(scope.textValue());
            }
            Map<String, Object> device = CanonicalJson.mapper().convertValue(
                    raw.get("device_keys"), Map.class);
            return new ServiceCredentials(
                    requiredText(raw, "service_id"),
                    requiredText(raw, "workspace_id"),
                    requiredText(raw, "name"),
                    scopes,
                    requiredText(raw, "enrollment_id"),
                    DeviceKeys.fromMap(device));
        } catch (IOException exception) {
            throw new IllegalArgumentException("Invalid Service credential data", exception);
        }
    }

    private static String requiredText(JsonNode value, String field) {
        JsonNode item = value.get(field);
        if (item == null || !item.isTextual() || item.textValue().isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return item.textValue();
    }

    private static String required(String field, String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }
}
