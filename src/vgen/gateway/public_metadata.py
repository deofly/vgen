"""Strict, plaintext-safe metadata accepted by the Gateway control plane.

The Gateway is an E2EE metadata service, not a generic JSON document store.
Keeping these validators independent from Pydantic lets both the HTTP boundary
and repository-internal callers enforce the same closed contract.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from vgen.artifacts.names import MEDIA_TYPE_EXTENSIONS
from vgen.protocol.media import MEDIA_PROBE_LIMITS

_PUBLIC_REQUIREMENT_KEYS = frozenset(
    {
        "operation",
        "payload_format",
        "executor_min_version",
        "runtime_min_version",
        "min_vram_bytes",
        "min_ram_bytes",
        "model_digests",
        "output_count",
    }
)
_MEDIA_METADATA_KEYS = frozenset(
    {
        "filename",
        "media_type",
        "width",
        "height",
        "frames",
        "duration_ms",
        "denoise_steps",
        "output_count",
    }
)
_OPERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_PAYLOAD_FORMAT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,119}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
# Worker reports are untrusted plaintext. Version-shaped free-form strings can
# still carry prompt fragments, so only bounded numeric release coordinates are
# persisted from a heartbeat. Owner-authored requirements keep the wider wire
# syntax above for compatibility.
_REPORTED_VERSION = re.compile(r"^(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){0,3}$")
_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{64}$")
_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_MEDIA_TYPE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}$"
)
_PUBLIC_MEDIA_TYPES = frozenset({*MEDIA_TYPE_EXTENSIONS, "application/octet-stream"})
_WORKFLOW_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,511}$")
_NODE_CLASS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_WORKFLOW_STATES = frozenset(
    {
        "ready",
        "missing_models",
        "missing_nodes",
        "node_probe_unavailable",
        "executor_incompatible",
        "runtime_incompatible",
        "insufficient_vram",
        "insufficient_ram",
    }
)
_MAINTENANCE_ACTIONS = (
    "worker_update",
    "model_install",
    "capability_install",
)
_PAYLOAD_FORMATS = (
    "comfyui-api-graph/v1",
    "fake/v1",
    "opaque/v1",
)
_OPERATIONS = (
    "t2v",
    "i2v",
    "flf",
    "t2i",
    "i2i",
    "text-to-video",
    "image-to-video",
)


@dataclass(frozen=True, slots=True)
class PublicMetadataError(ValueError):
    field: str
    reason: str

    def __str__(self) -> str:
        return f"{self.field}: {self.reason}"


def _mapping(value: object, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PublicMetadataError(field, "object_required")
    return value


def _closed_keys(value: Mapping[str, Any], allowed: frozenset[str], *, field: str) -> None:
    if any(not isinstance(key, str) or key not in allowed for key in value):
        # Do not reflect an attacker-controlled key. It could itself contain
        # prompt text or another secret.
        raise PublicMetadataError(field, "unsupported_field")


def _bounded_int(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PublicMetadataError(field, "integer_required")
    if value < minimum or value > maximum:
        raise PublicMetadataError(field, "integer_out_of_range")
    return value


def validate_public_requirements(value: object) -> dict[str, Any]:
    """Return the canonical closed set of non-sensitive scheduling facts."""

    raw = _mapping(value, field="public_requirements")
    _closed_keys(raw, _PUBLIC_REQUIREMENT_KEYS, field="public_requirements")
    if len(raw) > len(_PUBLIC_REQUIREMENT_KEYS):
        raise PublicMetadataError("public_requirements", "too_many_fields")

    result: dict[str, Any] = {}
    for name, pattern in (
        ("operation", _OPERATION),
        ("payload_format", _PAYLOAD_FORMAT),
        ("executor_min_version", _VERSION),
        ("runtime_min_version", _VERSION),
    ):
        if name not in raw:
            continue
        item = raw[name]
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise PublicMetadataError("public_requirements", f"invalid_{name}")
        result[name] = item

    for name, maximum in (
        ("min_vram_bytes", 1 << 60),
        ("min_ram_bytes", 1 << 60),
    ):
        if name in raw:
            result[name] = _bounded_int(
                raw[name], field="public_requirements", minimum=0, maximum=maximum
            )
    if "output_count" in raw:
        result["output_count"] = _bounded_int(
            raw["output_count"], field="public_requirements", minimum=1, maximum=8
        )

    if "model_digests" in raw:
        digests = raw["model_digests"]
        if not isinstance(digests, list) or len(digests) > 128:
            raise PublicMetadataError("public_requirements", "invalid_model_digests")
        canonical: list[str] = []
        seen: set[str] = set()
        for digest in digests:
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise PublicMetadataError("public_requirements", "invalid_model_digests")
            normalized = digest.lower()
            if not normalized.startswith("sha256:"):
                normalized = "sha256:" + normalized
            if normalized in seen:
                raise PublicMetadataError("public_requirements", "duplicate_model_digest")
            seen.add(normalized)
            canonical.append(normalized)
        result["model_digests"] = canonical
    return result


def validate_artifact_media_metadata(value: object) -> dict[str, Any]:
    """Return bounded media facts; reject free-form Worker/client prose."""

    return _validate_artifact_media_metadata(value, allow_unreviewed_type=False)


def validate_reported_artifact_media_metadata(value: object) -> dict[str, Any]:
    """Validate a legacy signed Worker report without changing its wire value."""

    return _validate_artifact_media_metadata(value, allow_unreviewed_type=True)


def project_reported_artifact_media_metadata(value: object) -> dict[str, Any]:
    """Drop private/unreviewed Worker strings after signature verification."""

    result = validate_reported_artifact_media_metadata(value)
    result.pop("filename", None)
    media_type = result.get("media_type")
    if not isinstance(media_type, str) or media_type.lower() not in _PUBLIC_MEDIA_TYPES:
        result.pop("media_type", None)
    else:
        result["media_type"] = media_type.lower()
    return result


def _validate_artifact_media_metadata(
    value: object,
    *,
    allow_unreviewed_type: bool,
) -> dict[str, Any]:

    raw = _mapping(value, field="media_metadata")
    _closed_keys(raw, _MEDIA_METADATA_KEYS, field="media_metadata")
    if len(raw) > len(_MEDIA_METADATA_KEYS):
        raise PublicMetadataError("media_metadata", "too_many_fields")

    result: dict[str, Any] = {}
    if "filename" in raw:
        filename = raw["filename"]
        if not isinstance(filename, str) or not _FILENAME.fullmatch(filename):
            raise PublicMetadataError("media_metadata", "invalid_filename")
        result["filename"] = filename
    if "media_type" in raw:
        media_type = raw["media_type"]
        if (
            not isinstance(media_type, str)
            or not _MEDIA_TYPE.fullmatch(media_type)
            or (not allow_unreviewed_type and media_type.lower() not in _PUBLIC_MEDIA_TYPES)
        ):
            raise PublicMetadataError("media_metadata", "invalid_media_type")
        # Preserve the signed wire value. Repository persistence performs the
        # lowercase projection only after Worker signature verification.
        result["media_type"] = media_type

    for name, (minimum, maximum) in MEDIA_PROBE_LIMITS.items():
        if name not in raw:
            continue
        if raw[name] is None:
            result[name] = None
            continue
        result[name] = _bounded_int(
            raw[name], field="media_metadata", minimum=minimum, maximum=maximum
        )
    return result


def canonical_worker_capabilities(
    value: object,
    *,
    executor_type: str,
) -> dict[str, Any]:
    """Project a Worker report onto the closed public scheduling contract.

    Capability reports originate on a machine that handles encrypted prompts
    and outputs.  Persisting the report recursively would turn every future
    plugin field into an accidental plaintext channel.  Unknown fields are
    therefore ignored, while every persisted string is a bounded protocol fact.
    """

    raw = _mapping(value, field="capabilities")
    if not raw:
        return {}

    result: dict[str, Any] = {}
    if "worker_runtime_version" in raw:
        result["worker_runtime_version"] = _protocol_string(
            raw["worker_runtime_version"],
            pattern=_REPORTED_VERSION,
            field="worker_runtime_version",
        )
    if "capability_install_spec_version" in raw:
        version = raw["capability_install_spec_version"]
        if type(version) is not int or version != 2:
            raise PublicMetadataError("capabilities", "invalid_capability_install_spec_version")
        result["capability_install_spec_version"] = version

    actions = raw.get("maintenance_actions", [])
    if not isinstance(actions, list) or len(actions) > len(_MAINTENANCE_ACTIONS):
        raise PublicMetadataError("capabilities", "invalid_maintenance_actions")
    if any(type(action) is not str or action not in _MAINTENANCE_ACTIONS for action in actions):
        raise PublicMetadataError("capabilities", "invalid_maintenance_actions")
    if len(actions) != len(set(actions)):
        raise PublicMetadataError("capabilities", "duplicate_maintenance_action")
    result["maintenance_actions"] = [action for action in _MAINTENANCE_ACTIONS if action in actions]

    executors = raw.get("executors", [])
    if not isinstance(executors, list) or len(executors) > 8:
        raise PublicMetadataError("capabilities", "invalid_executors")
    matching = [
        descriptor
        for descriptor in executors
        if isinstance(descriptor, Mapping) and descriptor.get("type") == executor_type
    ]
    if len(matching) > 1:
        raise PublicMetadataError("capabilities", "duplicate_executor")
    result["executors"] = (
        [_canonical_executor_descriptor(matching[0], executor_type=executor_type)]
        if matching
        else []
    )
    return result


def _protocol_string(value: object, *, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str):
        raise PublicMetadataError("capabilities", f"invalid_{field}")
    canonical = value.strip(" ")
    if not pattern.fullmatch(canonical):
        raise PublicMetadataError("capabilities", f"invalid_{field}")
    return canonical


def _canonical_known_string_list(
    value: object,
    *,
    allowed: tuple[str, ...],
    field: str,
    maximum: int,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise PublicMetadataError("capabilities", f"invalid_{field}")
    if any(not isinstance(item, str) for item in value):
        raise PublicMetadataError("capabilities", f"invalid_{field}")
    known = [item for item in value if item in allowed]
    if len(known) != len(set(known)):
        raise PublicMetadataError("capabilities", f"duplicate_{field}")
    return [item for item in allowed if item in known]


def _canonical_string_list(
    value: object,
    *,
    pattern: re.Pattern[str],
    field: str,
    maximum: int,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise PublicMetadataError("capabilities", f"invalid_{field}")
    result = [_protocol_string(item, pattern=pattern, field=field) for item in value]
    if len(result) != len(set(result)):
        raise PublicMetadataError("capabilities", f"duplicate_{field}")
    return result


def _canonical_digest_list(value: object, *, field: str, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise PublicMetadataError("capabilities", f"invalid_{field}")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _SHA256.fullmatch(item):
            raise PublicMetadataError("capabilities", f"invalid_{field}")
        digest = item.lower()
        result.append(digest if digest.startswith("sha256:") else "sha256:" + digest)
    if len(result) != len(set(result)):
        raise PublicMetadataError("capabilities", f"duplicate_{field}")
    return result


def _canonical_executor_descriptor(
    descriptor: Mapping[str, Any],
    *,
    executor_type: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {"type": executor_type}
    if "version" in descriptor:
        result["version"] = _protocol_string(
            descriptor["version"], pattern=_REPORTED_VERSION, field="executor_version"
        )
    result["payload_formats"] = _canonical_known_string_list(
        descriptor.get("payload_formats", []),
        allowed=_PAYLOAD_FORMATS,
        field="payload_formats",
        maximum=32,
    )
    result["operations"] = _canonical_known_string_list(
        descriptor.get("operations", []),
        allowed=_OPERATIONS,
        field="operations",
        maximum=32,
    )
    concurrency = descriptor.get("max_concurrency", 1)
    result["max_concurrency"] = _bounded_int(
        concurrency,
        field="capabilities",
        minimum=1,
        maximum=64,
    )
    nested = descriptor.get("capabilities", {})
    if not isinstance(nested, Mapping):
        raise PublicMetadataError("capabilities", "invalid_executor_capabilities")
    result["capabilities"] = _canonical_executor_capabilities(nested)
    return result


def _canonical_executor_capabilities(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    schema_version = value.get("capability_schema_version")
    if schema_version is not None:
        if type(schema_version) is not int or schema_version != 2:
            raise PublicMetadataError("capabilities", "invalid_capability_schema_version")
        result["capability_schema_version"] = 2

    result["model_digests"] = _canonical_digest_list(
        value.get("model_digests", []), field="model_digests", maximum=1024
    )
    readiness = _canonical_workflow_readiness(value.get("workflow_readiness", []))
    result["workflow_readiness"] = readiness
    derived_ready = [item["workflow_digest"] for item in readiness if item["state"] == "ready"]
    if "ready_workflow_digests" in value:
        reported_ready = _canonical_digest_list(
            value["ready_workflow_digests"],
            field="ready_workflow_digests",
            maximum=256,
        )
        if reported_ready != derived_ready:
            raise PublicMetadataError("capabilities", "inconsistent_ready_workflows")
    result["ready_workflow_digests"] = derived_ready

    for name in ("vram_bytes", "ram_bytes"):
        if name in value:
            result[name] = _bounded_int(
                value[name], field="capabilities", minimum=0, maximum=1 << 60
            )
    if "runtime_version" in value and value["runtime_version"] is not None:
        result["runtime_version"] = _protocol_string(
            value["runtime_version"], pattern=_REPORTED_VERSION, field="runtime_version"
        )

    # Older Workers may only report resource totals inside descriptive GPU and
    # system objects.  Derive the numeric facts without persisting device names,
    # operating-system strings, paths, or any other free-form values.
    if "vram_bytes" not in result:
        gpus = value.get("gpus", [])
        if not isinstance(gpus, list) or len(gpus) > 16:
            raise PublicMetadataError("capabilities", "invalid_gpus")
        totals: list[int] = []
        for gpu in gpus:
            if not isinstance(gpu, Mapping):
                raise PublicMetadataError("capabilities", "invalid_gpus")
            raw_total = gpu.get("vram_bytes", gpu.get("vram_total"))
            if isinstance(raw_total, int) and not isinstance(raw_total, bool) and raw_total >= 0:
                totals.append(raw_total)
                continue
            raw_megabytes = gpu.get("vram_total_mb")
            if (
                isinstance(raw_megabytes, (int, float))
                and not isinstance(raw_megabytes, bool)
                and math.isfinite(raw_megabytes)
                and raw_megabytes >= 0
            ):
                totals.append(int(raw_megabytes * 1024 * 1024))
        if totals:
            result["vram_bytes"] = min(max(totals), 1 << 60)
    if "ram_bytes" not in result:
        system = value.get("system")
        if system is not None and not isinstance(system, Mapping):
            raise PublicMetadataError("capabilities", "invalid_system")
        if isinstance(system, Mapping):
            raw_ram = system.get("ram_bytes", system.get("ram_total"))
            if (
                isinstance(raw_ram, int)
                and not isinstance(raw_ram, bool)
                and 0 <= raw_ram <= 1 << 60
            ):
                result["ram_bytes"] = raw_ram
            if "runtime_version" not in result and system.get("runtime_version") is not None:
                result["runtime_version"] = _protocol_string(
                    system["runtime_version"],
                    pattern=_REPORTED_VERSION,
                    field="runtime_version",
                )
    return result


def _canonical_workflow_readiness(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 256:
        raise PublicMetadataError("capabilities", "invalid_workflow_readiness")
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw in value:
        if not isinstance(raw, Mapping):
            raise PublicMetadataError("capabilities", "invalid_workflow_readiness")
        if "missing_model_digests" not in raw or "missing_node_classes" not in raw:
            raise PublicMetadataError("capabilities", "invalid_workflow_readiness")
        workflow_ref = _protocol_string(
            raw.get("workflow_ref"), pattern=_WORKFLOW_REF, field="workflow_ref"
        )
        digests = _canonical_digest_list(
            [raw.get("workflow_digest")], field="workflow_digest", maximum=1
        )
        state = raw.get("state")
        if not isinstance(state, str) or state not in _WORKFLOW_STATES:
            raise PublicMetadataError("capabilities", "invalid_workflow_state")
        missing_models = _canonical_digest_list(
            raw.get("missing_model_digests", []),
            field="missing_model_digests",
            maximum=1024,
        )
        missing_nodes = _canonical_string_list(
            raw.get("missing_node_classes", []),
            pattern=_NODE_CLASS,
            field="missing_node_classes",
            maximum=512,
        )
        # The Gateway may redact dependency identifiers that were not present
        # in an Owner-signed capability specification.  The fixed state still
        # communicates why the workflow is unavailable, while an empty list no
        # longer implies that the Worker was authorized to disclose names.
        if state == "ready" and (missing_models or missing_nodes):
            raise PublicMetadataError("capabilities", "inconsistent_workflow_state")
        identity = (workflow_ref, digests[0])
        if identity in seen:
            raise PublicMetadataError("capabilities", "duplicate_workflow_readiness")
        seen.add(identity)
        result.append(
            {
                "workflow_ref": workflow_ref,
                "workflow_digest": digests[0],
                "state": state,
                "missing_model_digests": missing_models,
                "missing_node_classes": missing_nodes,
            }
        )
    return result
