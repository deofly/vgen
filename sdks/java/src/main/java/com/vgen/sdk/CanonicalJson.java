package com.vgen.sdk;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Deterministic UTF-8 JSON matching VGen's Python canonical_json contract. */
public final class CanonicalJson {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Comparator<String> CODE_POINT_ORDER = CanonicalJson::compareCodePoints;

    private CanonicalJson() {}

    public static byte[] encode(Object value) {
        if (value == null) {
            throw new IllegalArgumentException("canonical JSON root is required");
        }
        try {
            JsonNode tree = value instanceof JsonNode node ? node : MAPPER.valueToTree(value);
            if (!tree.isObject() && !tree.isArray()) {
                throw new IllegalArgumentException("canonical JSON root must be an object or array");
            }
            return MAPPER.writeValueAsString(sorted(tree)).getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException("value cannot be encoded as canonical JSON", exception);
        }
    }

    public static String encodeToString(Object value) {
        return new String(encode(value), StandardCharsets.UTF_8);
    }

    static ObjectMapper mapper() {
        return MAPPER;
    }

    private static JsonNode sorted(JsonNode value) {
        if (value.isObject()) {
            ObjectNode result = MAPPER.createObjectNode();
            List<String> names = new ArrayList<>();
            value.fieldNames().forEachRemaining(names::add);
            names.sort(CODE_POINT_ORDER);
            for (String name : names) {
                result.set(name, sorted(value.get(name)));
            }
            return result;
        }
        if (value.isArray()) {
            ArrayNode result = MAPPER.createArrayNode();
            for (JsonNode item : value) {
                result.add(sorted(item));
            }
            return result;
        }
        if (value.isFloatingPointNumber() && !Double.isFinite(value.doubleValue())) {
            throw new IllegalArgumentException("canonical JSON does not allow NaN or Infinity");
        }
        return value;
    }

    private static int compareCodePoints(String left, String right) {
        int leftIndex = 0;
        int rightIndex = 0;
        while (leftIndex < left.length() && rightIndex < right.length()) {
            int leftCodePoint = left.codePointAt(leftIndex);
            int rightCodePoint = right.codePointAt(rightIndex);
            if (leftCodePoint != rightCodePoint) {
                return Integer.compare(leftCodePoint, rightCodePoint);
            }
            leftIndex += Character.charCount(leftCodePoint);
            rightIndex += Character.charCount(rightCodePoint);
        }
        return Integer.compare(left.length() - leftIndex, right.length() - rightIndex);
    }
}
