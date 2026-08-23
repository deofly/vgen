"""ComfyUI implementation of the generic Executor contract."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import mimetypes
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import unquote, urlsplit

import requests
import websocket
import yaml

from vgen.protocol import ErrorCode

from .base import (
    ExecutionArtifact,
    ExecutionCancelled,
    ExecutionContext,
    ExecutionRequest,
    ExecutionResult,
    ExecutorDescriptor,
    ExecutorFailure,
    ExecutorHealth,
    RetryAction,
    UsageMetrics,
)

logger = logging.getLogger("vgen.executors.comfyui")

COMFYUI_PAYLOAD_FORMAT = "comfyui-api-graph/v1"
OUTPUT_FIELDS = ("gifs", "videos", "images", "audio")
VIDEO_SUFFIXES = (".mp4", ".webm", ".mkv", ".mov", ".gif", ".avi")
MODEL_EXTENSIONS = (".safetensors", ".ckpt", ".gguf", ".bin", ".onnx", ".pt", ".pth")

_POLICY_FILE_MAX_BYTES = 256 * 1024
_HARD_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
_HARD_MAX_NODES = 512
_HARD_MAX_EDGES = 4096
_HARD_MAX_GRAPH_DEPTH = 128
_HARD_MAX_VALUE_DEPTH = 32
_HARD_MAX_INPUT_FIELDS = 256
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_PATH_FIELD_NAMES = frozenset(
    {
        "audio",
        "ckpt_name",
        "clip_name",
        "directory",
        "file",
        "filename",
        "filename_prefix",
        "folder",
        "image",
        "lora_name",
        "mask",
        "model",
        "model_name",
        "output_path",
        "path",
        "unet_name",
        "vae_name",
        "video",
    }
)
_PATH_FIELD_SUFFIXES = ("_path", "_file", "_filename", "_directory", "_folder")
_MODEL_FIELD_TOKENS = ("ckpt", "checkpoint", "clip", "controlnet", "lora", "model", "unet", "vae")
_MEDIA_FIELD_TOKENS = ("audio", "image", "images", "mask", "video")
_TEXT_FIELD_TOKENS = ("caption", "description", "prompt", "text")


class ComfyUIPolicyError(ValueError):
    """A safe, operator-facing local policy configuration error."""


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    values: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in values
        except TypeError as exc:
            raise ComfyUIPolicyError("ComfyUI policy keys must be scalar values.") from exc
        if duplicate:
            raise ComfyUIPolicyError("ComfyUI policy contains a duplicate key.")
        values[key] = loader.construct_object(value_node, deep=deep)
    return values


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class ComfyUIModelPin:
    path: str
    sha256: str
    size: int
    source: str | None = None
    revision: str | None = None
    license: str | None = None
    license_url: str | None = None
    gated: bool = False
    manual_download: bool = False


@dataclass(frozen=True)
class ModelVerificationProgress:
    model_index: int
    model_count: int
    path: str
    file_bytes_read: int
    file_size: int
    total_bytes_read: int
    total_size: int


@dataclass(frozen=True)
class ComfyUIExecutionPolicy:
    """Local machine-admin authorization for decrypted ComfyUI graphs.

    The Gateway and task author cannot widen this policy.  A workflow digest
    pin is optional defense in depth; every graph is still checked against the
    local node and structural allowlists because the public workflow digest is
    not itself a hash of the post-parameter-substitution graph.
    """

    allowed_node_classes: frozenset[str]
    allowed_custom_node_classes: frozenset[str] = frozenset()
    allowed_workflow_digests: frozenset[str] = frozenset()
    maintenance_workflows: tuple[tuple[str, str], ...] = ()
    model_files: tuple[ComfyUIModelPin, ...] = ()
    max_payload_bytes: int = 1024 * 1024
    max_nodes: int = 64
    max_edges: int = 256
    max_graph_depth: int = 32
    max_value_depth: int = 12
    max_input_fields_per_node: int = 64

    @classmethod
    def load(cls, path: Path) -> ComfyUIExecutionPolicy:
        expanded = path.expanduser()
        if expanded.is_symlink():
            raise ComfyUIPolicyError("ComfyUI policy file must not be a symbolic link.")
        try:
            metadata = expanded.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ComfyUIPolicyError("ComfyUI policy path must be a regular file.")
            if metadata.st_size > _POLICY_FILE_MAX_BYTES:
                raise ComfyUIPolicyError("ComfyUI policy file exceeds the size limit.")
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o022:
                raise ComfyUIPolicyError(
                    "ComfyUI policy file must not be writable by group or other users."
                )
            raw = expanded.read_text(encoding="utf-8")
        except ComfyUIPolicyError:
            raise
        except (OSError, UnicodeError) as exc:
            raise ComfyUIPolicyError("ComfyUI policy file cannot be read.") from exc
        try:
            # _UniqueKeySafeLoader subclasses yaml.SafeLoader and only adds
            # duplicate-key rejection; it cannot construct arbitrary objects.
            value = yaml.load(raw, Loader=_UniqueKeySafeLoader)  # nosec B506
        except ComfyUIPolicyError:
            raise
        except yaml.YAMLError as exc:
            raise ComfyUIPolicyError("ComfyUI policy file is not valid YAML or JSON.") from exc
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Any) -> ComfyUIExecutionPolicy:
        if not isinstance(value, Mapping):
            raise ComfyUIPolicyError("ComfyUI policy must be an object.")
        allowed_fields = {
            "version",
            "allowed_node_classes",
            "allowed_custom_node_classes",
            "allowed_workflow_digests",
            "maintenance_workflows",
            "models",
            "max_payload_bytes",
            "max_nodes",
            "max_edges",
            "max_graph_depth",
            "max_value_depth",
            "max_input_fields_per_node",
        }
        if set(value) - allowed_fields:
            raise ComfyUIPolicyError("ComfyUI policy contains an unknown setting.")
        if value.get("version") != 1:
            raise ComfyUIPolicyError("ComfyUI policy version must be 1.")

        builtin = _policy_strings(value.get("allowed_node_classes"), "allowed_node_classes")
        custom = _policy_strings(
            value.get("allowed_custom_node_classes", []),
            "allowed_custom_node_classes",
        )
        if not builtin and not custom:
            raise ComfyUIPolicyError("ComfyUI policy must allow at least one node class.")
        if builtin & custom:
            raise ComfyUIPolicyError(
                "A node class cannot be both built-in and explicitly approved custom code."
            )
        digests = _policy_strings(
            value.get("allowed_workflow_digests", []),
            "allowed_workflow_digests",
            pattern=_SHA256_DIGEST,
        )
        model_files = _policy_model_pins(value.get("models", []))
        maintenance_workflows = _policy_maintenance_workflows(
            value.get("maintenance_workflows", {})
        )
        return cls(
            allowed_node_classes=frozenset(builtin),
            allowed_custom_node_classes=frozenset(custom),
            allowed_workflow_digests=frozenset(digests),
            maintenance_workflows=maintenance_workflows,
            model_files=model_files,
            max_payload_bytes=_policy_limit(
                value, "max_payload_bytes", 1024 * 1024, _HARD_MAX_PAYLOAD_BYTES
            ),
            max_nodes=_policy_limit(value, "max_nodes", 64, _HARD_MAX_NODES),
            max_edges=_policy_limit(value, "max_edges", 256, _HARD_MAX_EDGES),
            max_graph_depth=_policy_limit(value, "max_graph_depth", 32, _HARD_MAX_GRAPH_DEPTH),
            max_value_depth=_policy_limit(value, "max_value_depth", 12, _HARD_MAX_VALUE_DEPTH),
            max_input_fields_per_node=_policy_limit(
                value,
                "max_input_fields_per_node",
                64,
                _HARD_MAX_INPUT_FIELDS,
            ),
        )

    def authorize_digest(self, workflow_digest: str) -> None:
        if self.allowed_workflow_digests and workflow_digest not in self.allowed_workflow_digests:
            raise _policy_denied("workflow_not_allowed")

    def authorize_graph(
        self,
        workflow: dict[str, Any],
        bindings: list[dict[str, Any]],
    ) -> None:
        if not workflow:
            raise _policy_denied("empty_graph")
        if len(workflow) > self.max_nodes:
            raise _policy_denied("graph_node_limit")

        allowed_classes = self.allowed_node_classes | self.allowed_custom_node_classes
        dependencies: dict[str, set[str]] = {node_id: set() for node_id in workflow}
        edge_count = 0
        for node_id, node in workflow.items():
            if not _SAFE_IDENTIFIER.fullmatch(node_id):
                raise _policy_denied("invalid_node_identifier")
            if set(node) - {"class_type", "inputs", "_meta"}:
                raise _policy_denied("unexpected_node_structure")
            class_type = node.get("class_type")
            inputs = node.get("inputs")
            metadata = node.get("_meta", {})
            if not isinstance(class_type, str) or not _SAFE_IDENTIFIER.fullmatch(class_type):
                raise _policy_denied("invalid_node_class")
            if class_type not in allowed_classes:
                raise _policy_denied("node_class_not_allowed")
            if not isinstance(inputs, dict) or not all(isinstance(key, str) for key in inputs):
                raise _policy_denied("invalid_node_inputs")
            if len(inputs) > self.max_input_fields_per_node:
                raise _policy_denied("node_input_limit")
            if (
                not isinstance(metadata, dict)
                or set(metadata) - {"title"}
                or (
                    "title" in metadata
                    and (
                        not isinstance(metadata["title"], str)
                        or len(metadata["title"]) > 256
                        or "\x00" in metadata["title"]
                    )
                )
            ):
                raise _policy_denied("invalid_node_metadata")

            for field, item in inputs.items():
                if not field or len(field) > 128 or "\x00" in field:
                    raise _policy_denied("invalid_input_field")
                found_dependencies, found_edges = self._inspect_value(
                    item,
                    field=field,
                    workflow=workflow,
                    depth=0,
                )
                edge_count += found_edges
                dependencies[node_id].update(found_dependencies)
                if edge_count > self.max_edges:
                    raise _policy_denied("graph_edge_limit")

        self._validate_dependency_graph(dependencies)
        self._validate_bindings(workflow, bindings)

    def _inspect_value(
        self,
        value: Any,
        *,
        field: str,
        workflow: Mapping[str, Any],
        depth: int,
    ) -> tuple[set[str], int]:
        if depth > self.max_value_depth:
            raise _policy_denied("graph_value_depth_limit")
        if _is_connection_candidate(value):
            if not _looks_like_connection(value):
                raise _policy_denied("invalid_node_connection")
            dependency = value[0]
            if dependency not in workflow:
                raise _policy_denied("dangling_node_connection")
            return {dependency}, 1
        if isinstance(value, str):
            if len(value.encode("utf-8")) > self.max_payload_bytes:
                raise _policy_denied("graph_value_size_limit")
            if _is_path_semantic_field(field):
                _validate_local_relative_path(value)
            return set(), 0
        if isinstance(value, float) and not math.isfinite(value):
            raise _policy_denied("invalid_numeric_value")
        if value is None or isinstance(value, (bool, int, float)):
            return set(), 0
        if isinstance(value, list):
            if len(value) > self.max_edges:
                raise _policy_denied("graph_sequence_limit")
            dependencies: set[str] = set()
            edge_count = 0
            for item in value:
                nested_dependencies, nested_edges = self._inspect_value(
                    item,
                    field=field,
                    workflow=workflow,
                    depth=depth + 1,
                )
                dependencies.update(nested_dependencies)
                edge_count += nested_edges
            return dependencies, edge_count
        if isinstance(value, dict):
            dependencies = set()
            edge_count = 0
            if len(value) > self.max_input_fields_per_node:
                raise _policy_denied("graph_mapping_limit")
            for nested_field, item in value.items():
                if not isinstance(nested_field, str) or len(nested_field) > 128:
                    raise _policy_denied("invalid_nested_field")
                nested_dependencies, nested_edges = self._inspect_value(
                    item,
                    field=nested_field,
                    workflow=workflow,
                    depth=depth + 1,
                )
                dependencies.update(nested_dependencies)
                edge_count += nested_edges
            return dependencies, edge_count
        raise _policy_denied("unsupported_graph_value")

    def _validate_dependency_graph(self, dependencies: Mapping[str, set[str]]) -> None:
        visiting: set[str] = set()
        complete: set[str] = set()
        memo: dict[str, int] = {}

        def depth(node_id: str) -> int:
            if node_id in visiting:
                raise _policy_denied("cyclic_graph")
            if node_id in complete:
                return memo[node_id]
            visiting.add(node_id)
            value = 1 + max((depth(item) for item in dependencies[node_id]), default=0)
            visiting.remove(node_id)
            complete.add(node_id)
            memo[node_id] = value
            if value > self.max_graph_depth:
                raise _policy_denied("graph_depth_limit")
            return value

        for node_id in dependencies:
            depth(node_id)

    def _validate_bindings(
        self,
        workflow: Mapping[str, Any],
        bindings: list[dict[str, Any]],
    ) -> None:
        if len(bindings) > self.max_nodes:
            raise _policy_denied("input_binding_limit")
        targets: set[str] = set()
        for binding in bindings:
            if set(binding) - {"input", "node_id", "node_title", "field"}:
                raise _policy_denied("invalid_input_binding")
            input_name = binding.get("input")
            node_id = binding.get("node_id")
            node_title = binding.get("node_title")
            field = binding.get("field", "image")
            if not isinstance(input_name, str) or not _SAFE_IDENTIFIER.fullmatch(input_name):
                raise _policy_denied("invalid_input_binding")
            if field != "image":
                raise _policy_denied("invalid_input_binding_field")
            if node_id is None and node_title is None:
                raise _policy_denied("invalid_input_binding")
            if node_id is not None and (
                not isinstance(node_id, str) or not _SAFE_IDENTIFIER.fullmatch(node_id)
            ):
                raise _policy_denied("invalid_input_binding")
            if node_title is not None and (
                not isinstance(node_title, str) or len(node_title) > 256 or "\x00" in node_title
            ):
                raise _policy_denied("invalid_input_binding")
            matches = [
                candidate_id
                for candidate_id, node in workflow.items()
                if (node_id is None or candidate_id == node_id)
                and (node_title is None or (node.get("_meta") or {}).get("title") == node_title)
            ]
            if len(matches) != 1 or workflow[matches[0]].get("class_type") != "LoadImage":
                raise _policy_denied("input_binding_target_not_allowed")
            if matches[0] in targets:
                raise _policy_denied("duplicate_input_binding")
            targets.add(matches[0])
        load_image_nodes = {
            node_id for node_id, node in workflow.items() if node.get("class_type") == "LoadImage"
        }
        if load_image_nodes - targets:
            raise _policy_denied("unbound_load_image")


def _policy_strings(
    value: Any,
    field: str,
    *,
    pattern: re.Pattern[str] = _SAFE_IDENTIFIER,
) -> set[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and pattern.fullmatch(item) for item in value
    ):
        raise ComfyUIPolicyError(f"ComfyUI policy {field} must be a list of safe identifiers.")
    if len(value) != len(set(value)) or len(value) > 1024:
        raise ComfyUIPolicyError(f"ComfyUI policy {field} contains duplicate or excess entries.")
    return set(value)


def _policy_maintenance_workflows(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or len(value) > 128:
        raise ComfyUIPolicyError("ComfyUI policy maintenance_workflows must be a bounded object.")
    result: list[tuple[str, str]] = []
    for raw_ref, raw_digest in value.items():
        if (
            not isinstance(raw_ref, str)
            or not 1 <= len(raw_ref) <= 512
            or "@" not in raw_ref
            or any(character in raw_ref for character in ("\x00", "\r", "\n", " "))
            or not isinstance(raw_digest, str)
            or not _SHA256_DIGEST.fullmatch(raw_digest)
        ):
            raise ComfyUIPolicyError("ComfyUI policy maintenance workflow binding is invalid.")
        result.append((raw_ref, raw_digest))
    return tuple(sorted(result))


def _policy_model_pins(value: Any) -> tuple[ComfyUIModelPin, ...]:
    if not isinstance(value, list) or len(value) > 128:
        raise ComfyUIPolicyError("ComfyUI policy models must be a bounded list.")
    pins: list[ComfyUIModelPin] = []
    seen_paths: set[str] = set()
    seen_digests: set[str] = set()
    for item in value:
        required_fields = {"path", "sha256", "size"}
        optional_fields = {
            "source",
            "revision",
            "license",
            "license_url",
            "gated",
            "manual_download",
        }
        if (
            not isinstance(item, Mapping)
            or not required_fields.issubset(item)
            or set(item) - required_fields - optional_fields
        ):
            raise ComfyUIPolicyError("Each ComfyUI policy model needs path, sha256, and size.")
        raw_path = item.get("path")
        raw_digest = item.get("sha256")
        raw_size = item.get("size")
        if not isinstance(raw_path, str):
            raise ComfyUIPolicyError("ComfyUI policy model path is invalid.")
        normalized_path = raw_path.replace("\\", "/")
        path = PurePosixPath(normalized_path)
        if (
            not normalized_path
            or normalized_path.startswith("/")
            or _URI_SCHEME.match(normalized_path)
            or PureWindowsPath(raw_path).drive
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ComfyUIPolicyError("ComfyUI policy model path must stay under the model root.")
        if not isinstance(raw_digest, str) or not _SHA256_DIGEST.fullmatch(raw_digest):
            raise ComfyUIPolicyError("ComfyUI policy model sha256 is invalid.")
        if (
            not isinstance(raw_size, int)
            or isinstance(raw_size, bool)
            or raw_size < 1
            or raw_size > 1024**5
        ):
            raise ComfyUIPolicyError("ComfyUI policy model size is invalid.")
        if normalized_path in seen_paths or raw_digest in seen_digests:
            raise ComfyUIPolicyError("ComfyUI policy model pins must be unique.")
        source = _optional_policy_https_url(item.get("source"), "source")
        license_url = _optional_policy_https_url(item.get("license_url"), "license URL")
        revision = _optional_policy_metadata(item.get("revision"), "revision")
        license_id = _optional_policy_metadata(item.get("license"), "license")
        gated = item.get("gated", False)
        manual_download = item.get("manual_download", False)
        if not isinstance(gated, bool) or not isinstance(manual_download, bool):
            raise ComfyUIPolicyError("ComfyUI policy model flags must be boolean values.")
        if source is not None and revision is None:
            raise ComfyUIPolicyError(
                "A downloadable ComfyUI policy model needs an immutable revision."
            )
        if manual_download and (source is None or license_id is None or license_url is None):
            raise ComfyUIPolicyError(
                "A manual ComfyUI model download needs source and license metadata."
            )
        seen_paths.add(normalized_path)
        seen_digests.add(raw_digest)
        pins.append(
            ComfyUIModelPin(
                path=path.as_posix(),
                sha256=raw_digest.removeprefix("sha256:"),
                size=raw_size,
                source=source,
                revision=revision,
                license=license_id,
                license_url=license_url,
                gated=gated,
                manual_download=manual_download,
            )
        )
    return tuple(pins)


def _optional_policy_metadata(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise ComfyUIPolicyError(f"ComfyUI policy model {label} is invalid.")
    return value


def _optional_policy_https_url(value: Any, label: str) -> str | None:
    normalized = _optional_policy_metadata(value, label)
    if normalized is None:
        return None
    try:
        parsed = urlsplit(normalized)
        _ = parsed.port
    except ValueError as exc:
        raise ComfyUIPolicyError(f"ComfyUI policy model {label} is invalid.") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ComfyUIPolicyError(f"ComfyUI policy model {label} must use safe HTTPS.")
    return normalized


def _policy_limit(value: Mapping[str, Any], field: str, default: int, maximum: int) -> int:
    result = value.get(field, default)
    if not isinstance(result, int) or isinstance(result, bool) or not 1 <= result <= maximum:
        raise ComfyUIPolicyError(f"ComfyUI policy {field} is outside its safe range.")
    return result


def _policy_denied(reason: str) -> ExecutorFailure:
    return ExecutorFailure(
        ErrorCode.UNSUPPORTED_PAYLOAD,
        "UNSUPPORTED_PAYLOAD",
        "The decrypted ComfyUI workflow is not authorized by this Worker.",
        details={"reason": reason},
    )


def _looks_like_connection(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and isinstance(value[0], str)
        and isinstance(value[1], int)
        and not isinstance(value[1], bool)
        and value[1] >= 0
    )


def _is_connection_candidate(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and isinstance(value[0], str)
        and isinstance(value[1], int)
    )


def _is_path_semantic_field(field: str) -> bool:
    normalized = field.casefold().replace("-", "_")
    tokens = frozenset(item for item in normalized.split("_") if item)
    if (
        normalized in _PATH_FIELD_NAMES
        or normalized.endswith((*_PATH_FIELD_SUFFIXES, "_dir", "_prefix", "_uri", "_url"))
        or tokens & {"dir", "directory", "file", "filename", "folder", "path", "uri", "url"}
    ):
        return True
    if tokens & set(_TEXT_FIELD_TOKENS):
        return False
    if tokens & set(_MODEL_FIELD_TOKENS) or tokens & set(_MEDIA_FIELD_TOKENS):
        return True
    return normalized.endswith("_name") and any(
        token in normalized for token in _MODEL_FIELD_TOKENS
    )


def _validate_local_relative_path(value: str) -> None:
    decoded = unquote(value)
    if not decoded:
        return
    if (
        len(decoded) > 2048
        or any(character in decoded for character in ("\x00", "\r", "\n"))
        or decoded.startswith("~")
        or _URI_SCHEME.match(decoded)
        or PurePosixPath(decoded).is_absolute()
        or PureWindowsPath(decoded).is_absolute()
        or bool(PurePosixPath(decoded).root)
        or bool(PureWindowsPath(decoded).root)
        or bool(PureWindowsPath(decoded).drive)
        or any(segment == ".." for segment in re.split(r"[\\/]", decoded))
    ):
        raise _policy_denied("unsafe_local_path")


class _ComfyProtocolError(Exception):
    def __init__(self, reason: str, *, status_code: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


class _ComfyTimeout(Exception):
    pass


class _ComfyCancelled(Exception):
    pass


@dataclass(frozen=True)
class ComfyOutput:
    filename: str
    subfolder: str
    kind: str

    @property
    def is_video(self) -> bool:
        return self.filename.lower().endswith(VIDEO_SUFFIXES)


@dataclass(frozen=True)
class ComfyRunResult:
    prompt_id: str
    outputs: tuple[ComfyOutput, ...]


class ComfyUIClient:
    """Small ComfyUI HTTP/WebSocket client with no Worker/Gateway knowledge."""

    def __init__(self, base_url: str, session: requests.Session | None = None) -> None:
        self._base = base_url.rstrip("/")
        self._session = session or requests.Session()

    def ping(self) -> None:
        response = self._session.get(f"{self._base}/system_stats", timeout=10)
        response.raise_for_status()

    def gpu_info(self) -> list[dict[str, Any]]:
        try:
            response = self._session.get(f"{self._base}/system_stats", timeout=10)
            response.raise_for_status()
            devices = response.json().get("devices") or []
            return [
                {
                    "name": device.get("name"),
                    "vram_total_mb": round((device.get("vram_total") or 0) / 1048576),
                }
                for device in devices
                if isinstance(device, dict)
            ]
        except (requests.RequestException, ValueError, KeyError):
            return []

    def system_info(self) -> dict[str, Any]:
        """Return only non-sensitive scheduling facts from ComfyUI system stats."""

        try:
            response = self._session.get(f"{self._base}/system_stats", timeout=10)
            response.raise_for_status()
            system = response.json().get("system") or {}
            if not isinstance(system, dict):
                return {}
            ram_total = system.get("ram_total")
            result: dict[str, Any] = {}
            if isinstance(ram_total, int) and not isinstance(ram_total, bool) and ram_total >= 0:
                result["ram_bytes"] = ram_total
            os_name = system.get("os")
            if isinstance(os_name, str) and os_name:
                result["os"] = os_name[:64]
            runtime_version = system.get("comfyui_version")
            if isinstance(runtime_version, str) and runtime_version:
                result["runtime_version"] = runtime_version[:64]
            return result
        except (requests.RequestException, ValueError, KeyError):
            return {}

    def models_catalog(self) -> set[str] | None:
        try:
            response = self._session.get(f"{self._base}/models", timeout=15)
            response.raise_for_status()
            folders = response.json()
            if not isinstance(folders, list):
                return None
            names: set[str] = set()
            for folder in folders:
                if not isinstance(folder, str):
                    continue
                try:
                    listing = self._session.get(f"{self._base}/models/{folder}", timeout=15)
                    listing.raise_for_status()
                    names.update(
                        item
                        for item in listing.json()
                        if isinstance(item, str) and item.lower().endswith(MODEL_EXTENSIONS)
                    )
                except (requests.RequestException, ValueError):
                    continue
            if names:
                return names
        except (requests.RequestException, ValueError):
            pass

        try:
            response = self._session.get(f"{self._base}/object_info", timeout=120)
            response.raise_for_status()
            names = set()
            for node in response.json().values():
                if not isinstance(node, dict):
                    continue
                inputs = node.get("input") or {}
                for group in (inputs.get("required") or {}, inputs.get("optional") or {}):
                    if not isinstance(group, dict):
                        continue
                    for spec in group.values():
                        if isinstance(spec, (list, tuple)) and spec and isinstance(spec[0], list):
                            names.update(
                                item
                                for item in spec[0]
                                if isinstance(item, str) and item.lower().endswith(MODEL_EXTENSIONS)
                            )
            return names
        except (requests.RequestException, ValueError, KeyError):
            return None

    def upload_image(self, path: Path, name: str) -> tuple[str, str]:
        with path.open("rb") as stream:
            response = self._session.post(
                f"{self._base}/upload/image",
                files={"image": (Path(name).name, stream)},
                data={"overwrite": "true"},
                timeout=180,
            )
        if response.status_code >= 400:
            raise _ComfyProtocolError("input_upload_rejected", status_code=response.status_code)
        try:
            payload = response.json()
            return str(payload["name"]), str(payload.get("subfolder") or "")
        except (ValueError, KeyError, TypeError) as exc:
            raise _ComfyProtocolError("invalid_input_upload_response") from exc

    def interrupt(self) -> None:
        try:
            self._session.post(f"{self._base}/interrupt", timeout=10)
        except requests.RequestException:
            logger.warning("ComfyUI interrupt request failed")

    def run(
        self,
        workflow: dict[str, Any],
        on_progress: Callable[[float, str], None],
        should_cancel: Callable[[], bool],
        timeout: float,
    ) -> ComfyRunResult:
        client_id = uuid.uuid4().hex
        ws = websocket.WebSocket()
        ws.settimeout(1.0)
        try:
            ws.connect(self._ws_url(client_id), timeout=15)
            prompt_id = self._submit(workflow, client_id)
            self._wait(ws, prompt_id, on_progress, should_cancel, timeout)
        finally:
            try:
                ws.close()
            except Exception:  # pragma: no cover - websocket cleanup is best effort
                logger.debug("ComfyUI websocket cleanup failed", exc_info=True)
        return ComfyRunResult(prompt_id, tuple(self._collect_outputs(prompt_id)))

    def _ws_url(self, client_id: str) -> str:
        base = self._base.replace("https://", "wss://").replace("http://", "ws://")
        return f"{base}/ws?clientId={client_id}"

    def _submit(self, workflow: dict[str, Any], client_id: str) -> str:
        response = self._session.post(
            f"{self._base}/prompt",
            json={"prompt": workflow, "client_id": client_id},
            timeout=60,
        )
        if response.status_code >= 400:
            raise _ComfyProtocolError("workflow_rejected", status_code=response.status_code)
        try:
            body = response.json()
            if body.get("node_errors"):
                raise _ComfyProtocolError("node_validation_failed")
            return str(body["prompt_id"])
        except (ValueError, KeyError, TypeError) as exc:
            raise _ComfyProtocolError("invalid_prompt_response") from exc

    def _wait(
        self,
        ws: websocket.WebSocket,
        prompt_id: str,
        on_progress: Callable[[float, str], None],
        should_cancel: Callable[[], bool],
        timeout: float,
    ) -> None:
        deadline = time.monotonic() + timeout
        stage = "queued"
        fraction = 0.0
        last_tick = 0.0
        websocket_closed = False

        while True:
            if time.monotonic() > deadline:
                self.interrupt()
                raise _ComfyTimeout()
            if should_cancel():
                self.interrupt()
                raise _ComfyCancelled()

            raw: str | bytes | None
            if websocket_closed:
                if self._history(prompt_id) is not None:
                    on_progress(1.0, "sampled")
                    return
                time.sleep(1)
                raw = None
            else:
                try:
                    raw = ws.recv()
                except websocket.WebSocketTimeoutException:
                    raw = None
                except websocket.WebSocketConnectionClosedException:
                    logger.warning("ComfyUI websocket closed; falling back to history polling")
                    websocket_closed = True
                    raw = None

            now = time.monotonic()
            if now - last_tick >= 1.0:
                last_tick = now
                on_progress(fraction, stage)

            if not raw or isinstance(raw, bytes):
                continue
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            kind = message.get("type")
            data = message.get("data") or {}
            if data.get("prompt_id") not in (None, prompt_id):
                continue
            if kind == "execution_start":
                stage = "sampling"
            elif kind == "executing":
                if data.get("node") is None and data.get("prompt_id") == prompt_id:
                    on_progress(1.0, "sampled")
                    return
                stage = f"node:{data.get('node')}"
            elif kind == "progress":
                total = data.get("max") or 1
                fraction = min(float(data.get("value", 0)) / float(total), 1.0)
                stage = "sampling"
            elif kind == "execution_error":
                error_type = str(data.get("exception_type") or "execution_error")
                raise _ComfyProtocolError(error_type)
            elif kind == "execution_interrupted":
                raise _ComfyCancelled()
            elif kind == "execution_success":
                on_progress(1.0, "sampled")
                return

    def _history(self, prompt_id: str) -> dict[str, Any] | None:
        response = self._session.get(f"{self._base}/history/{prompt_id}", timeout=30)
        response.raise_for_status()
        return response.json().get(prompt_id)

    def _collect_outputs(self, prompt_id: str) -> list[ComfyOutput]:
        entry = None
        for _ in range(8):
            entry = self._history(prompt_id)
            if entry is not None:
                break
            time.sleep(2)
        if entry is None:
            raise _ComfyProtocolError("history_missing")

        outputs: list[ComfyOutput] = []
        for node_output in (entry.get("outputs") or {}).values():
            for field in OUTPUT_FIELDS:
                for item in node_output.get(field) or []:
                    if not isinstance(item, dict) or "filename" not in item:
                        continue
                    output = ComfyOutput(
                        filename=str(item["filename"]),
                        subfolder=str(item.get("subfolder") or ""),
                        kind=str(item.get("type") or "output"),
                    )
                    if output.kind == "output":
                        outputs.append(output)
        if not outputs:
            raise _ComfyProtocolError("no_output")
        videos = [output for output in outputs if output.is_video]
        return videos or outputs


class ComfyUIExecutor:
    """Adapter which contains every ComfyUI-specific payload assumption."""

    requires_execution_policy = True

    def __init__(
        self,
        base_url: str,
        output_dir: Path,
        *,
        client: ComfyUIClient | None = None,
        policy: ComfyUIExecutionPolicy | None = None,
        model_root: Path | None = None,
        model_verification_progress: Callable[[ModelVerificationProgress], None] | None = None,
    ) -> None:
        self._client = client or ComfyUIClient(base_url)
        self._output_dir = output_dir.expanduser().resolve()
        self._policy = policy
        self._model_root = (
            model_root.expanduser().resolve()
            if model_root is not None
            else (self._output_dir.parent / "models").resolve()
        )
        self._model_digest_cache: dict[Path, tuple[int, int, int, int, int, str]] = {}
        self._model_verification_progress = model_verification_progress

    @property
    def execution_policy_configured(self) -> bool:
        return self._policy is not None

    @property
    def maintenance_model_pins(self) -> tuple[ComfyUIModelPin, ...]:
        """Return only locally authorized model pins to the maintenance runtime.

        A Gateway job can select a digest from this tuple, but it cannot supply
        or widen the source, destination, license, or integrity policy.
        """

        return self._policy.model_files if self._policy is not None else ()

    @property
    def maintenance_workflows(self) -> tuple[tuple[str, str], ...]:
        """Exact package-ref to digest bindings allowed to request models."""

        return self._policy.maintenance_workflows if self._policy is not None else ()

    @property
    def maintenance_model_root(self) -> Path:
        """Return the locally selected model root; never sourced from a job."""

        return self._model_root

    def invalidate_model_digest_cache(self) -> None:
        """Force the next capability report to observe newly installed files."""

        self._model_digest_cache.clear()

    def descriptor(self) -> ExecutorDescriptor:
        return ExecutorDescriptor(
            executor_type="comfyui",
            version="1.1.0",
            payload_formats=(COMFYUI_PAYLOAD_FORMAT,),
            operations=("t2v", "i2v", "flf", "t2i", "i2i"),
            max_concurrency=1,
        )

    def health(self) -> ExecutorHealth:
        try:
            self._client.ping()
            return ExecutorHealth(True, "ready")
        except (requests.RequestException, websocket.WebSocketException, OSError) as exc:
            return ExecutorHealth(False, "unavailable", details={"error_type": type(exc).__name__})

    def capabilities(self) -> Mapping[str, Any]:
        model_digests, model_failures = self._verified_model_digests()
        gpus = self._client.gpu_info()
        system_info = getattr(self._client, "system_info", None)
        system = system_info() if callable(system_info) else {}
        vram_bytes = max(
            (
                int(gpu.get("vram_total_mb", 0) * 1024 * 1024)
                for gpu in gpus
                if isinstance(gpu, dict)
                and isinstance(gpu.get("vram_total_mb"), (int, float))
                and not isinstance(gpu.get("vram_total_mb"), bool)
            ),
            default=0,
        )
        return {
            "executor_type": "comfyui",
            "payload_formats": [COMFYUI_PAYLOAD_FORMAT],
            "model_digests": model_digests,
            "gpus": gpus,
            "vram_bytes": vram_bytes,
            "ram_bytes": int(system.get("ram_bytes", 0)),
            "runtime_version": system.get("runtime_version"),
            "system": system,
            "execution_policy": {
                "configured": self.execution_policy_configured,
                "model_pins": len(self._policy.model_files) if self._policy is not None else 0,
                "models_verified": len(model_digests),
                "models_failed": model_failures,
            },
        }

    def _verified_model_digests(self) -> tuple[list[str], int]:
        pins = self._policy.model_files if self._policy is not None else ()
        verified: list[str] = []
        failures = 0
        total_size = sum(pin.size for pin in pins)
        total_bytes_read = 0
        last_reported_total_percent = -1

        def report(
            *,
            model_index: int,
            pin: ComfyUIModelPin,
            file_bytes_read: int,
            force: bool = False,
        ) -> None:
            nonlocal last_reported_total_percent
            if self._model_verification_progress is None:
                return
            total_percent = (
                100 if total_size == 0 else int(total_bytes_read * 100 / total_size)
            )
            if not force and total_percent <= last_reported_total_percent:
                return
            last_reported_total_percent = total_percent
            self._model_verification_progress(
                ModelVerificationProgress(
                    model_index=model_index,
                    model_count=len(pins),
                    path=pin.path,
                    file_bytes_read=file_bytes_read,
                    file_size=pin.size,
                    total_bytes_read=total_bytes_read,
                    total_size=total_size,
                )
            )

        for model_index, pin in enumerate(pins, start=1):
            candidate = (self._model_root / pin.path).resolve()
            if self._model_root != candidate and self._model_root not in candidate.parents:
                failures += 1
                continue
            try:
                metadata = candidate.stat()
            except OSError:
                failures += 1
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != pin.size:
                failures += 1
                continue
            cached = self._model_digest_cache.get(candidate)
            fingerprint = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            if cached is not None and cached[:5] == fingerprint:
                digest = cached[5]
            else:
                hasher = hashlib.sha256()
                file_bytes_read = 0
                report(model_index=model_index, pin=pin, file_bytes_read=0, force=True)
                try:
                    with candidate.open("rb") as stream:
                        while block := stream.read(8 * 1024 * 1024):
                            hasher.update(block)
                            file_bytes_read += len(block)
                            total_bytes_read += len(block)
                            report(
                                model_index=model_index,
                                pin=pin,
                                file_bytes_read=file_bytes_read,
                            )
                except OSError:
                    failures += 1
                    continue
                digest = hasher.hexdigest()
                report(
                    model_index=model_index,
                    pin=pin,
                    file_bytes_read=file_bytes_read,
                    force=True,
                )
                after = candidate.stat()
                if (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ) != fingerprint:
                    failures += 1
                    continue
                self._model_digest_cache[candidate] = (*fingerprint, digest)
            if digest != pin.sha256:
                failures += 1
                continue
            verified.append(f"sha256:{digest}")
        return sorted(verified), failures

    def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
        descriptor = self.descriptor()
        if request.payload_format not in descriptor.payload_formats:
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "The ComfyUI executor does not support this payload format.",
                details={"payload_format": request.payload_format},
            )
        if request.operation not in descriptor.operations:
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "The ComfyUI executor does not support this operation.",
                details={"operation": request.operation},
            )
        if self._policy is not None and self._policy.model_files:
            verified_models, model_failures = self._verified_model_digests()
            if model_failures or len(verified_models) != len(self._policy.model_files):
                raise ExecutorFailure(
                    ErrorCode.DEPENDENCY_MISSING,
                    "DEPENDENCY_MISSING",
                    "A locally pinned ComfyUI model is missing or failed integrity verification.",
                    details={"reason": "model_integrity_unavailable"},
                )

        if self._policy is None:
            raise _policy_denied("policy_required")
        self._policy.authorize_digest(request.workflow_digest)
        if len(request.payload) > self._policy.max_payload_bytes:
            raise _policy_denied("payload_size_limit")
        workflow, bindings = self._decode_payload(request.payload)
        self._policy.authorize_graph(workflow, bindings)
        context.raise_if_cancelled()
        for binding in bindings:
            self._bind_input(workflow, request, binding)

        started = time.monotonic()
        try:
            run = self._client.run(
                workflow,
                on_progress=lambda fraction, stage: context.progress(fraction, stage),
                should_cancel=context.is_cancelled,
                timeout=request.timeout_seconds,
            )
        except _ComfyCancelled as exc:
            raise ExecutionCancelled() from exc
        except _ComfyTimeout as exc:
            raise ExecutorFailure(
                ErrorCode.EXECUTION_TIMEOUT,
                "EXECUTION_TIMEOUT",
                "ComfyUI execution exceeded its deadline.",
                retry_action=RetryAction.ANOTHER_WORKER,
            ) from exc
        except (requests.RequestException, websocket.WebSocketException, OSError) as exc:
            raise ExecutorFailure(
                ErrorCode.EXECUTOR_UNAVAILABLE,
                "EXECUTOR_UNAVAILABLE",
                "ComfyUI is unavailable.",
                retry_action=RetryAction.SAME_WORKER,
                details={"error_type": type(exc).__name__},
            ) from exc
        except _ComfyProtocolError as exc:
            raise self._map_protocol_error(exc) from exc

        elapsed_ms = max(1, round((time.monotonic() - started) * 1000))
        artifacts: list[ExecutionArtifact] = []
        total_bytes = 0
        aggregate: dict[str, Any] = {}
        for index, output in enumerate(run.outputs):
            path = self._resolve_output(output)
            total_bytes += path.stat().st_size
            media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            media = _probe_media(path)
            if index == 0:
                aggregate.update(media)
            artifacts.append(
                ExecutionArtifact(
                    name="primary" if index == 0 else f"output-{index + 1}",
                    path=path,
                    media_type=media_type,
                    metadata=media,
                )
            )
        usage = UsageMetrics(
            executor_wall_ms=elapsed_ms,
            # ComfyUI does not expose reliable GPU-active time.  The signed
            # report keeps it absent instead of misrepresenting wall time.
            gpu_active_ms=None,
            output_bytes=total_bytes,
            frames=aggregate.get("frames"),
            duration_ms=aggregate.get("duration_ms"),
        )
        return ExecutionResult(
            tuple(artifacts),
            usage=usage,
            executor_run_id=run.prompt_id,
            metadata={"output_count": len(artifacts)},
        )

    def cancel(self, handle: str | None = None) -> None:
        # ComfyUI's interrupt endpoint is process-global.  The descriptor keeps
        # max_concurrency=1 so an interrupt cannot affect another attempt.
        self._client.interrupt()

    @staticmethod
    def _decode_payload(payload: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        try:
            body = json.loads(payload.decode("utf-8"))
            workflow = body["workflow"]
            bindings = body.get("input_bindings") or []
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "The ComfyUI payload is not a valid API workflow package.",
            ) from exc
        if not isinstance(workflow, dict) or not all(
            isinstance(node_id, str) and isinstance(node, dict)
            for node_id, node in workflow.items()
        ):
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "The ComfyUI workflow must be an API-format object.",
            )
        if not isinstance(bindings, list) or not all(isinstance(item, dict) for item in bindings):
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "ComfyUI input bindings must be a list.",
            )
        return workflow, bindings

    def _bind_input(
        self,
        workflow: dict[str, Any],
        request: ExecutionRequest,
        binding: dict[str, Any],
    ) -> None:
        input_name = binding.get("input")
        node_id = binding.get("node_id")
        node_title = binding.get("node_title")
        field = binding.get("field") or "image"
        if (
            not isinstance(input_name, str)
            or not _SAFE_IDENTIFIER.fullmatch(input_name)
            or field != "image"
        ):
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "ComfyUI input binding is incomplete.",
            )
        execution_input = next((item for item in request.inputs if item.name == input_name), None)
        if execution_input is None:
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "A required ComfyUI input artifact is missing.",
            )
        matches: list[dict[str, Any]] = []
        for candidate_id, node in workflow.items():
            if node_id is not None and candidate_id != str(node_id):
                continue
            if node_title is not None and (node.get("_meta") or {}).get("title") != node_title:
                continue
            matches.append(node)
        if len(matches) != 1 or matches[0].get("class_type") != "LoadImage":
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "A ComfyUI input binding did not resolve to exactly one node.",
                details={"reason": "input_binding_target_not_allowed"},
            )
        upload_name = f"vgen_{uuid.uuid4().hex}{execution_input.path.suffix[:16]}"
        try:
            comfy_name, subfolder = self._client.upload_image(execution_input.path, upload_name)
        except requests.RequestException as exc:
            raise ExecutorFailure(
                ErrorCode.EXECUTOR_UNAVAILABLE,
                "EXECUTOR_UNAVAILABLE",
                "ComfyUI could not receive an input artifact.",
                retry_action=RetryAction.SAME_WORKER,
                details={"error_type": type(exc).__name__},
            ) from exc
        except _ComfyProtocolError as exc:
            raise self._map_protocol_error(exc) from exc
        _validate_local_relative_path(comfy_name)
        if subfolder:
            _validate_local_relative_path(subfolder)
        reference = f"{subfolder}/{comfy_name}" if subfolder else comfy_name
        matches[0].setdefault("inputs", {})[field] = reference

    def _resolve_output(self, output: ComfyOutput) -> Path:
        candidate = (self._output_dir / output.subfolder / output.filename).resolve()
        if not _is_relative_to(candidate, self._output_dir):
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "ComfyUI returned an output path outside its configured directory.",
            )
        if candidate.is_file():
            return candidate
        basename = Path(output.filename).name
        for match in self._output_dir.rglob(basename):
            resolved = match.resolve()
            if _is_relative_to(resolved, self._output_dir) and resolved.is_file():
                return resolved
        raise ExecutorFailure(
            ErrorCode.DEPENDENCY_MISSING,
            "DEPENDENCY_MISSING",
            "ComfyUI reported an output which is not available on the worker filesystem.",
            retry_action=RetryAction.SAME_WORKER,
        )

    @staticmethod
    def _map_protocol_error(error: _ComfyProtocolError) -> ExecutorFailure:
        reason = error.reason.lower()
        if "outofmemory" in reason or "out_of_memory" in reason or "cuda" in reason:
            return ExecutorFailure(
                ErrorCode.GPU_OUT_OF_MEMORY,
                "GPU_OUT_OF_MEMORY",
                "ComfyUI ran out of GPU memory.",
                retry_action=RetryAction.ANOTHER_WORKER,
            )
        if reason in {"workflow_rejected", "node_validation_failed", "invalid_prompt_response"}:
            return ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "ComfyUI rejected the workflow payload.",
                details={"reason": reason, "status_code": error.status_code},
            )
        if reason in {"no_output", "history_missing"}:
            return ExecutorFailure(
                ErrorCode.DEPENDENCY_MISSING,
                "DEPENDENCY_MISSING",
                "ComfyUI did not produce an accessible output artifact.",
                retry_action=RetryAction.SAME_WORKER,
                details={"reason": reason},
            )
        return ExecutorFailure(
            ErrorCode.DEPENDENCY_MISSING,
            "DEPENDENCY_MISSING",
            "ComfyUI execution failed because its local environment is incomplete.",
            retry_action=RetryAction.SAME_WORKER,
            details={"reason": "local_execution_failed", "status_code": error.status_code},
        )


def _probe_media(path: Path) -> dict[str, int]:
    ffprobe = shutil.which("ffprobe")
    if ffprobe:
        try:
            completed = subprocess.run(
                [
                    ffprobe,
                    "-v",
                    "error",
                    "-select_streams",
                    "v:0",
                    "-show_entries",
                    "stream=width,height,nb_frames",
                    "-show_entries",
                    "format=duration",
                    "-of",
                    "json",
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            payload = json.loads(completed.stdout)
            stream = (payload.get("streams") or [{}])[0]
            duration = (payload.get("format") or {}).get("duration")
            result: dict[str, int] = {}
            if stream.get("width"):
                result["width"] = int(stream["width"])
                result["height"] = int(stream["height"])
            if stream.get("nb_frames") and str(stream["nb_frames"]).isdigit():
                result["frames"] = int(stream["nb_frames"])
            if duration:
                result["duration_ms"] = round(float(duration) * 1000)
            return result
        except (subprocess.SubprocessError, json.JSONDecodeError, ValueError, KeyError):
            pass

    # ComfyUI Desktop installations do not always expose ffprobe on PATH, but
    # the supported Windows runtime already provides OpenCV. Use it as a local
    # fallback so output video duration does not silently become zero.
    try:
        import cv2
    except ImportError:
        return {}
    capture = cv2.VideoCapture(str(path))
    try:
        if not capture.isOpened():
            return {}
        frames = max(0, round(capture.get(cv2.CAP_PROP_FRAME_COUNT)))
        fps = capture.get(cv2.CAP_PROP_FPS)
        width = max(0, round(capture.get(cv2.CAP_PROP_FRAME_WIDTH)))
        height = max(0, round(capture.get(cv2.CAP_PROP_FRAME_HEIGHT)))
        result = {}
        if width and height:
            result.update({"width": width, "height": height})
        if frames:
            result["frames"] = frames
        if frames and fps > 0 and math.isfinite(fps):
            result["duration_ms"] = round(frames / fps * 1000)
        return result
    finally:
        capture.release()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
