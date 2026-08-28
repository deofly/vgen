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
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import unquote, urlsplit

import requests
import websocket
import yaml
from jsonschema import Draft202012Validator
from packaging.version import InvalidVersion, Version

from vgen.market.builder import WorkflowBuildError, build_comfy_graph
from vgen.market.capabilities import WorkflowCapabilityError, comfyui_capability_facts
from vgen.market.paths import canonical_package_path, package_path_key
from vgen.market.registry import InstallResult
from vgen.protocol import ErrorCode
from vgen.protocol.diagnostics import SAFE_TASK_FAILURE_COMPONENTS

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
# FAT-compatible volumes can expose a two-second modification-time tick. A
# fresh stat identity must settle for that full tick before cross-probe reuse.
_MODEL_DIGEST_CACHE_SETTLE_NS = 2_000_000_000
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SAFE_PROVENANCE_ENTRY = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
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


def _custom_node_probe_budget(repository_count: int) -> float:
    return min(30.0, 5.0 + 2.5 * repository_count)


def _provenance_error(reason: str, entry: str | None = None) -> str:
    if entry is not None and _SAFE_PROVENANCE_ENTRY.fullmatch(entry):
        return f"{reason}:{entry}"
    return reason


def _canonical_git_source(source: str) -> str:
    canonical = source.rstrip("/")
    return canonical[:-4] if canonical.casefold().endswith(".git") else canonical


def _is_reparse_point(path: Path) -> bool:
    """Return true for symlinks and Windows junction/reparse entries."""

    try:
        metadata = path.lstat()
    except OSError:
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


_PROTOCOL_FAILURE_REASONS = frozenset(
    {
        "gpu_out_of_memory",
        "history_missing",
        "input_upload_rejected",
        "invalid_input_upload_response",
        "invalid_prompt_response",
        "local_execution_failed",
        "model_load_incompatible",
        "model_not_found",
        "no_output",
        "node_class_missing",
        "node_runtime_error",
        "node_validation_failed",
        "python_dependency_missing",
        "system_out_of_memory",
        "tensor_shape_mismatch",
        "workflow_rejected",
    }
)


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
class ComfyUICustomNodePin:
    """Executable dependency whose exact local Git checkout must be proven."""

    name: str
    source: str
    revision: str
    node_types: frozenset[str]
    node_pack: str | None = None
    node_pack_sha256: str | None = None


@dataclass(frozen=True)
class ComfyUIWorkflowCapability:
    workflow_ref: str
    workflow_digest: str
    policy: ComfyUIExecutionPolicy
    executor_min_version: str | None = None
    runtime_min_version: str | None = None
    operations: frozenset[str] = frozenset()
    template_graph: dict[str, Any] | None = None
    mapping: dict[str, Any] | None = None
    parameter_schema: dict[str, Any] | None = None
    min_vram_bytes: int | None = None
    min_ram_bytes: int | None = None
    custom_nodes: tuple[ComfyUICustomNodePin, ...] = ()


class CapabilitySource:
    """Narrow structural contract implemented by WorkerCapabilityStore."""

    def active(self) -> tuple[InstallResult, ...]:  # pragma: no cover - protocol shape only
        raise NotImplementedError

    def generation(self) -> object:  # pragma: no cover
        raise NotImplementedError


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
    custom_nodes: tuple[ComfyUICustomNodePin, ...] = ()
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
            "custom_nodes",
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
        custom_nodes = _policy_custom_node_pins(value.get("custom_nodes", []))
        pinned_node_types = {
            node_type for dependency in custom_nodes for node_type in dependency.node_types
        }
        if not pinned_node_types <= custom:
            raise ComfyUIPolicyError(
                "ComfyUI policy custom-node pins must reference approved custom node classes."
            )
        maintenance_workflows = _policy_maintenance_workflows(
            value.get("maintenance_workflows", {})
        )
        return cls(
            allowed_node_classes=frozenset(builtin),
            allowed_custom_node_classes=frozenset(custom),
            allowed_workflow_digests=frozenset(digests),
            maintenance_workflows=maintenance_workflows,
            model_files=model_files,
            custom_nodes=custom_nodes,
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
    digest_sizes: dict[str, int] = {}
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
        try:
            normalized_path = canonical_package_path(
                raw_path,
                label="ComfyUI policy model path",
                allow_backslash=True,
            )
        except ValueError as exc:
            raise ComfyUIPolicyError(
                "ComfyUI policy model path must stay under the model root."
            ) from exc
        if not isinstance(raw_digest, str) or not _SHA256_DIGEST.fullmatch(raw_digest):
            raise ComfyUIPolicyError("ComfyUI policy model sha256 is invalid.")
        if (
            not isinstance(raw_size, int)
            or isinstance(raw_size, bool)
            or raw_size < 1
            or raw_size > 1024**5
        ):
            raise ComfyUIPolicyError("ComfyUI policy model size is invalid.")
        path_key = package_path_key(normalized_path, label="ComfyUI policy model path")
        previous_size = digest_sizes.get(raw_digest)
        if path_key in seen_paths or (previous_size is not None and previous_size != raw_size):
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
        if manual_download and source is None:
            raise ComfyUIPolicyError("A manual ComfyUI model download needs a provenance source.")
        seen_paths.add(path_key)
        digest_sizes[raw_digest] = raw_size
        pins.append(
            ComfyUIModelPin(
                path=normalized_path,
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


def _policy_custom_node_pins(value: Any) -> tuple[ComfyUICustomNodePin, ...]:
    if not isinstance(value, list) or len(value) > 8:
        raise ComfyUIPolicyError("ComfyUI policy custom_nodes must be a bounded list.")
    pins: list[ComfyUICustomNodePin] = []
    identities: set[tuple[str, str]] = set()
    claimed_node_types: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "name",
            "source",
            "revision",
            "node_types",
        }:
            raise ComfyUIPolicyError("ComfyUI policy custom-node pin is invalid.")
        name = item.get("name")
        source = item.get("source")
        revision = item.get("revision")
        node_types = item.get("node_types")
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 120
            or not isinstance(source, str)
            or not source.startswith("https://")
            or len(source) > 512
            or not isinstance(revision, str)
            or re.fullmatch(r"[0-9a-f]{40}", revision) is None
            or not isinstance(node_types, list)
            or not 1 <= len(node_types) <= 128
            or any(
                not isinstance(node, str) or not _SAFE_IDENTIFIER.fullmatch(node)
                for node in node_types
            )
            or len(node_types) != len(set(node_types))
        ):
            raise ComfyUIPolicyError("ComfyUI policy custom-node pin is invalid.")
        identity = (source, revision)
        if identity in identities or claimed_node_types & set(node_types):
            raise ComfyUIPolicyError("ComfyUI policy custom-node pins must be unique.")
        identities.add(identity)
        claimed_node_types.update(node_types)
        pins.append(
            ComfyUICustomNodePin(
                name=name,
                source=source,
                revision=revision,
                node_types=frozenset(node_types),
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


def _minimum_version_satisfied(actual: object, minimum: str | None) -> bool:
    if minimum is None:
        return True
    if not isinstance(actual, str):
        return False
    try:
        return Version(actual) >= Version(minimum)
    except InvalidVersion:
        return False


def _workflow_capability(installed: InstallResult) -> ComfyUIWorkflowCapability:
    try:
        facts = comfyui_capability_facts(installed.manifest, installed.path)
    except WorkflowCapabilityError as exc:
        raise ComfyUIPolicyError("An active workflow capability graph is invalid.") from exc
    variant = facts.variant
    graph = facts.graph
    mapping = facts.mapping
    node_classes = facts.node_classes
    parameter_schema = installed.manifest.parameters
    try:
        Draft202012Validator.check_schema(parameter_schema)
    except Exception as exc:
        raise ComfyUIPolicyError(
            "An active workflow capability parameter schema is invalid."
        ) from exc
    properties = parameter_schema.get("properties", {})
    if not isinstance(properties, dict) or set(mapping) != set(properties):
        raise ComfyUIPolicyError(
            "An active workflow capability must map every declared parameter exactly once."
        )
    mapping_targets: dict[str, tuple[str, str]] = {}
    for name, rule in mapping.items():
        mapping_targets[name] = _capability_mapping_target(graph, rule, name=name)
    if len(set(mapping_targets.values())) != len(mapping_targets):
        raise ComfyUIPolicyError(
            "An active workflow capability maps multiple parameters to one input."
        )

    declared_custom = {
        node_type for dependency in variant.custom_nodes for node_type in dependency.node_types
    }
    custom = node_classes & declared_custom
    builtin = node_classes - custom
    seen_model_paths: set[str] = set()
    model_sizes: dict[str, int] = {}
    for model in variant.models:
        model_path = f"{model.folder}/{model.filename}"
        model_path_key = package_path_key(model_path)
        if model.size < 1 or model_path_key in seen_model_paths:
            raise ComfyUIPolicyError(
                "An active workflow capability has duplicate or empty model pins."
            )
        previous_size = model_sizes.get(model.sha256)
        if previous_size is not None and previous_size != model.size:
            raise ComfyUIPolicyError(
                "An active workflow capability has conflicting shared model sizes."
            )
        seen_model_paths.add(model_path_key)
        model_sizes[model.sha256] = model.size
    models = tuple(
        ComfyUIModelPin(
            path=f"{model.folder}/{model.filename}",
            sha256=model.sha256,
            size=model.size,
            source=model.source,
            revision=model.revision,
            license=model.license,
            gated=model.gated,
            manual_download=model.manual_download,
        )
        for model in variant.models
    )
    expected_model_references = {model.filename.replace("\\", "/") for model in variant.models}
    actual_model_references = _model_references(graph)
    if actual_model_references != expected_model_references:
        raise ComfyUIPolicyError(
            "An active workflow capability must bind every model pin to its exact graph path."
        )
    for node_id, field in mapping_targets.values():
        original = graph[node_id]["inputs"][field]
        if isinstance(original, str) and original.replace("\\", "/") in actual_model_references:
            raise ComfyUIPolicyError(
                "An active workflow capability cannot expose a pinned model loader as a parameter."
            )
    workflow_ref = f"{installed.manifest.id}@{installed.manifest.version}"
    workflow_digest = f"sha256:{installed.digest}"
    edge_count = sum(
        1
        for node in graph.values()
        if isinstance(node, dict)
        for value in (node.get("inputs") or {}).values()
        if _looks_like_connection(value)
    )
    policy = ComfyUIExecutionPolicy(
        allowed_node_classes=frozenset(builtin),
        allowed_custom_node_classes=frozenset(custom),
        allowed_workflow_digests=frozenset({workflow_digest}),
        maintenance_workflows=((workflow_ref, workflow_digest),),
        model_files=models,
        max_payload_bytes=min(
            _HARD_MAX_PAYLOAD_BYTES, max(1024 * 1024, len(json.dumps(graph)) * 2)
        ),
        max_nodes=min(_HARD_MAX_NODES, max(64, len(graph))),
        max_edges=min(_HARD_MAX_EDGES, max(256, edge_count * 2)),
        max_graph_depth=32,
        max_value_depth=12,
        max_input_fields_per_node=64,
    )
    capability = ComfyUIWorkflowCapability(
        workflow_ref=workflow_ref,
        workflow_digest=workflow_digest,
        policy=policy,
        executor_min_version=variant.executor_min_version,
        runtime_min_version=variant.runtime_min_version,
        operations=frozenset(variant.operations),
        template_graph=graph,
        mapping=mapping,
        parameter_schema=parameter_schema,
        min_vram_bytes=variant.min_vram_bytes,
        min_ram_bytes=variant.min_ram_bytes,
        custom_nodes=tuple(
            ComfyUICustomNodePin(
                name=dependency.name,
                source=dependency.source,
                revision=dependency.revision,
                node_types=frozenset(dependency.node_types),
                node_pack=dependency.node_pack,
                node_pack_sha256=dependency.node_pack_sha256,
            )
            for dependency in variant.custom_nodes
        ),
    )
    # Compile every declared topology through the same package binding used at
    # execution time. Optional image nodes are therefore removed (or retained)
    # exactly as the reviewed mapping declares before the release is activated.
    for operation in capability.operations:
        sample_parameters = _sample_operation_parameters(operation, mapping)
        try:
            sample_graph, effective, derived_operation = build_comfy_graph(
                graph, mapping, sample_parameters
            )
        except WorkflowBuildError as exc:
            raise ComfyUIPolicyError(
                "An active workflow capability mapping cannot build its declared operations."
            ) from exc
        if operation in {"t2v", "i2v", "flf"} and derived_operation != operation:
            raise ComfyUIPolicyError(
                "An active workflow capability operation does not match its mapping."
            )
        bindings = _capability_expected_bindings(sample_graph, mapping, effective)
        policy.authorize_graph(sample_graph, bindings)
    return capability


def _conflicting_model_placement_digests(
    capabilities: Iterable[ComfyUIWorkflowCapability],
    *,
    static_policy: ComfyUIExecutionPolicy | None,
) -> set[str]:
    """Return dynamic releases that disagree on machine-wide model paths.

    The local machine-admin policy is represented by a ``None`` owner and is
    always authoritative.  Grouping all identities before deciding conflicts
    also handles three-way collisions deterministically instead of depending
    on activation or dictionary order.
    """

    placements: dict[
        str,
        dict[tuple[str, int], set[str | None]],
    ] = {}
    digest_sizes: dict[str, dict[int, set[str | None]]] = {}

    def add(pin: ComfyUIModelPin, owner: str | None) -> None:
        key = package_path_key(pin.path, label="ComfyUI model path")
        identities = placements.setdefault(key, {})
        identities.setdefault((pin.sha256, pin.size), set()).add(owner)
        digest_sizes.setdefault(pin.sha256, {}).setdefault(pin.size, set()).add(owner)

    if static_policy is not None:
        for pin in static_policy.model_files:
            add(pin, None)
    for capability in capabilities:
        for pin in capability.policy.model_files:
            add(pin, capability.workflow_digest)

    placement_conflicts = {
        owner
        for identities in placements.values()
        if len(identities) > 1
        for owners in identities.values()
        for owner in owners
        if owner is not None
    }
    size_conflicts = {
        owner
        for sizes in digest_sizes.values()
        if len(sizes) > 1
        for owners in sizes.values()
        for owner in owners
        if owner is not None
    }
    return placement_conflicts | size_conflicts


def _capability_mapping_target(
    graph: Mapping[str, Any],
    rule: Any,
    *,
    name: str,
    allow_connection: bool = False,
) -> tuple[str, str]:
    if not isinstance(rule, dict) or set(rule) - {
        "node",
        "title",
        "input",
        "optional_connection",
    }:
        raise ComfyUIPolicyError(f"Workflow parameter mapping {name!r} is invalid.")
    node_selector = rule.get("node")
    title_selector = rule.get("title")
    if (node_selector is None) == (title_selector is None):
        raise ComfyUIPolicyError(f"Workflow parameter mapping {name!r} is ambiguous.")
    if node_selector is not None:
        if isinstance(node_selector, bool) or not isinstance(node_selector, (str, int)):
            raise ComfyUIPolicyError(f"Workflow parameter mapping {name!r} is invalid.")
        node_id = str(node_selector)
        if node_id not in graph:
            raise ComfyUIPolicyError(f"Workflow parameter mapping {name!r} has no node.")
    else:
        if (
            not isinstance(title_selector, str)
            or not title_selector
            or len(title_selector) > 256
            or "\x00" in title_selector
        ):
            raise ComfyUIPolicyError(f"Workflow parameter mapping {name!r} is invalid.")
        matches = [
            candidate_id
            for candidate_id, node in graph.items()
            if isinstance(node, dict) and (node.get("_meta") or {}).get("title") == title_selector
        ]
        if len(matches) != 1:
            raise ComfyUIPolicyError(f"Workflow parameter mapping {name!r} must select one node.")
        node_id = matches[0]
    node = graph.get(node_id)
    inputs = node.get("inputs") if isinstance(node, dict) else None
    candidates = rule.get("input")
    if isinstance(candidates, str):
        candidates = [candidates]
    if (
        not isinstance(candidates, list)
        or not candidates
        or len(candidates) > 16
        or any(
            not isinstance(candidate, str) or not _SAFE_IDENTIFIER.fullmatch(candidate)
            for candidate in candidates
        )
        or len(candidates) != len(set(candidates))
        or not isinstance(inputs, dict)
    ):
        raise ComfyUIPolicyError(f"Workflow parameter mapping {name!r} has no safe input.")
    fields = [candidate for candidate in candidates if candidate in inputs]
    if not fields:
        raise ComfyUIPolicyError(f"Workflow parameter mapping {name!r} has no input.")
    field = fields[0]
    if _looks_like_connection(inputs[field]) and not allow_connection:
        raise ComfyUIPolicyError(f"Workflow parameter mapping {name!r} targets a connected input.")
    optional = rule.get("optional_connection")
    if optional is not None:
        if name not in {"image", "last_image"} or not isinstance(optional, dict):
            raise ComfyUIPolicyError(
                f"Workflow parameter mapping {name!r} has an invalid optional connection."
            )
        if set(optional) - {"target_node", "target_title", "input", "output"}:
            raise ComfyUIPolicyError(
                f"Workflow parameter mapping {name!r} has an invalid optional connection."
            )
        target_rule = {
            "node": optional.get("target_node"),
            "title": optional.get("target_title"),
            "input": optional.get("input"),
        }
        target_id, target_field = _capability_mapping_target(
            graph,
            target_rule,
            name=f"{name}.optional_connection",
            allow_connection=True,
        )
        output = optional.get("output", 0)
        if not isinstance(output, int) or isinstance(output, bool) or output < 0:
            raise ComfyUIPolicyError(
                f"Workflow parameter mapping {name!r} has an invalid optional output."
            )
        if graph[target_id]["inputs"].get(target_field) != [node_id, output]:
            raise ComfyUIPolicyError(
                f"Workflow parameter mapping {name!r} does not match its connection."
            )
    return node_id, field


def _model_references(value: Any) -> set[str]:
    if isinstance(value, str):
        normalized = value.replace("\\", "/")
        return {normalized} if normalized.casefold().endswith(MODEL_EXTENSIONS) else set()
    if isinstance(value, list):
        return set().union(*(_model_references(item) for item in value), set())
    if isinstance(value, dict):
        return set().union(*(_model_references(item) for item in value.values()), set())
    return set()


def _sample_operation_parameters(operation: str, mapping: Mapping[str, Any]) -> dict[str, Any]:
    parameters: dict[str, Any] = {}
    if operation in {"i2v", "i2i", "flf"} and "image" in mapping:
        parameters["image"] = "vgen-input.png"
    if operation == "flf" and "last_image" in mapping:
        parameters["last_image"] = "vgen-last-input.png"
    return parameters


def _capability_expected_bindings(
    graph: Mapping[str, Any],
    mapping: Mapping[str, Any],
    parameters: Mapping[str, Any],
) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for name in ("image", "last_image"):
        if not parameters.get(name):
            continue
        rule = mapping.get(name)
        node_id, field = _capability_mapping_target(graph, rule, name=name)
        bindings.append({"input": name, "node_id": node_id, "field": field})
    return bindings


def _normalized_bindings(
    graph: Mapping[str, Any], bindings: list[dict[str, Any]]
) -> tuple[tuple[str, str, str], ...]:
    normalized: list[tuple[str, str, str]] = []
    for binding in bindings:
        input_name = binding.get("input")
        node_id = binding.get("node_id")
        node_title = binding.get("node_title")
        field = binding.get("field", "image")
        matches = [
            candidate_id
            for candidate_id, node in graph.items()
            if (node_id is None or candidate_id == str(node_id))
            and (
                node_title is None
                or (isinstance(node, dict) and (node.get("_meta") or {}).get("title") == node_title)
            )
        ]
        if not isinstance(input_name, str) or not isinstance(field, str) or len(matches) != 1:
            raise _policy_denied("workflow_bindings_mismatch")
        normalized.append((input_name, matches[0], field))
    return tuple(sorted(normalized))


def _policy_denied(reason: str) -> ExecutorFailure:
    return ExecutorFailure(
        ErrorCode.UNSUPPORTED_PAYLOAD,
        "UNSUPPORTED_PAYLOAD",
        "The decrypted ComfyUI workflow is not authorized by this Worker.",
        details={"reason": reason},
    )


def _provider_environment_failure(reason: str, message: str) -> ExecutorFailure:
    """Return a fixed provider-side error for local Worker misconfiguration."""

    return ExecutorFailure(
        ErrorCode.EXECUTOR_UNAVAILABLE,
        "EXECUTOR_UNAVAILABLE",
        message,
        retry_action=RetryAction.SAME_WORKER,
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


def _diagnostic_text(*values: Any) -> str:
    """Build bounded, local-only text used solely for fixed error classification."""

    return " ".join(value[:4096].casefold() for value in values if isinstance(value, str) and value)


def _classify_execution_failure(exception_type: Any, exception_message: Any) -> str:
    diagnostic = _diagnostic_text(exception_type, exception_message)
    compact = re.sub(r"[^a-z0-9]+", "", diagnostic)

    out_of_memory = (
        "outofmemory" in compact
        or "memoryerror" in compact
        or "stdbadalloc" in compact
        or "cannot allocate memory" in diagnostic
        or "memory allocation failed" in diagnostic
        or "defaultcpuallocator" in compact
    )
    gpu_memory = any(
        marker in compact for marker in ("cuda", "cublas", "cudnn", "hipoutofmemory", "rocm")
    )
    if out_of_memory and gpu_memory:
        return "gpu_out_of_memory"
    if out_of_memory:
        return "system_out_of_memory"
    if (
        "modulenotfounderror" in compact
        or "importerror" in compact
        or "no module named" in diagnostic
        or "cannot import name" in diagnostic
        or "dll load failed while importing" in diagnostic
    ):
        return "python_dependency_missing"
    if any(
        marker in diagnostic
        for marker in (
            "shape mismatch",
            "shapes cannot be multiplied",
            "size mismatch",
            "must match the size",
            "dimension out of range",
            "invalid for input of size",
        )
    ):
        return "tensor_shape_mismatch"
    if any(
        marker in compact for marker in ("safetensorerror", "gguferror", "modelloaderror")
    ) or any(
        marker in diagnostic
        for marker in (
            "invalid header",
            "header too large",
            "state_dict",
            "state dict",
            "unsupported model format",
            "unsupported checkpoint",
        )
    ):
        return "model_load_incompatible"
    return "node_runtime_error"


def _diagnostic_component(node_type: Any) -> str | None:
    """Map a local node class to a fixed, non-encoding diagnostic role."""

    if not isinstance(node_type, str):
        return None
    tokens = {
        token.casefold()
        for token in re.findall(
            r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[0-9]+",
            node_type,
        )
    }
    if "loader" in tokens:
        return "model_loader"
    if "sampler" in tokens:
        return "sampler"
    if "decode" in tokens or "decoder" in tokens:
        return "decoder"
    if "encode" in tokens or "encoder" in tokens:
        return "encoder"
    if tokens & {"combine", "output", "preview", "save"}:
        return "output"
    return None


def _is_model_validation_error(error: Mapping[str, Any]) -> bool:
    error_type = _diagnostic_text(error.get("type"))
    extra_info = error.get("extra_info")
    input_name = extra_info.get("input_name") if isinstance(extra_info, dict) else None
    diagnostic = _diagnostic_text(
        error.get("message"),
        error.get("details"),
        input_name,
    )
    normalized_input = (
        input_name.casefold().replace("-", "_") if isinstance(input_name, str) else ""
    )
    model_input = any(token in normalized_input for token in _MODEL_FIELD_TOKENS)
    names_model_file = any(extension in diagnostic for extension in MODEL_EXTENSIONS)
    explicit_missing_model = any(
        marker in error_type
        for marker in ("model_not_found", "missing_model", "checkpoint_not_found")
    )
    return explicit_missing_model or (
        "value_not_in_list" in error_type and (model_input or names_model_file)
    )


def _classify_validation_failure(
    node_errors: Any,
    global_error: Any,
) -> tuple[str, str | None]:
    """Classify an HTTP prompt rejection without retaining upstream prose."""

    candidates: list[tuple[str | None, Mapping[str, Any]]] = []
    if isinstance(node_errors, dict):
        for raw_node in node_errors.values():
            if not isinstance(raw_node, dict):
                continue
            component = _diagnostic_component(raw_node.get("class_type"))
            errors = raw_node.get("errors")
            if isinstance(errors, list):
                for error in errors:
                    if isinstance(error, dict):
                        candidates.append((component, error))
            if not isinstance(errors, list) or not errors:
                candidates.append((component, {}))

    global_mapping = global_error if isinstance(global_error, dict) else {}
    global_diagnostic = _diagnostic_text(
        global_mapping.get("type"),
        global_mapping.get("message"),
        global_mapping.get("details"),
    )
    if "node" in global_diagnostic and any(
        marker in global_diagnostic for marker in ("does not exist", "not found")
    ):
        return "node_class_missing", None

    priority = {"model_not_found": 0, "node_class_missing": 1, "node_validation_failed": 10}
    best: tuple[int, str, str | None] | None = None
    for component, error in candidates:
        if _is_model_validation_error(error):
            reason = "model_not_found"
        else:
            diagnostic = _diagnostic_text(
                error.get("type"), error.get("message"), error.get("details")
            )
            reason = (
                "node_class_missing"
                if "node" in diagnostic
                and any(marker in diagnostic for marker in ("does not exist", "not found"))
                else "node_validation_failed"
            )
        candidate = (priority[reason], reason, component)
        if best is None or candidate[0] < best[0]:
            best = candidate
    if best is not None:
        return best[1], best[2]

    return "node_validation_failed", None


class _ComfyProtocolError(Exception):
    """A protocol failure containing only bounded, publishable diagnostics."""

    def __init__(
        self,
        reason: str,
        *,
        status_code: int | None = None,
        component: Any = None,
    ) -> None:
        safe_reason = reason if reason in _PROTOCOL_FAILURE_REASONS else "local_execution_failed"
        safe_status = (
            status_code if isinstance(status_code, int) and 100 <= status_code <= 599 else None
        )
        super().__init__(safe_reason)
        self.reason = safe_reason
        self.status_code = safe_status
        self.component = (
            component
            if isinstance(component, str) and component in SAFE_TASK_FAILURE_COMPONENTS
            else None
        )

    def safe_details(self) -> dict[str, str]:
        details = {"reason": self.reason}
        if self.component is not None:
            details["component"] = self.component
        return details


class _ComfyTimeout(Exception):
    pass


class _ComfyCancelled(Exception):
    pass


def _execution_protocol_error(data: Any) -> _ComfyProtocolError:
    payload = data if isinstance(data, dict) else {}
    return _ComfyProtocolError(
        _classify_execution_failure(
            payload.get("exception_type"),
            payload.get("exception_message"),
        ),
        component=_diagnostic_component(payload.get("node_type")),
    )


def _history_failure(entry: Any) -> _ComfyProtocolError | _ComfyCancelled | None:
    if not isinstance(entry, dict):
        return None
    status = entry.get("status")
    if not isinstance(status, dict):
        return None
    messages = status.get("messages")
    if isinstance(messages, list):
        for message in reversed(messages):
            if not isinstance(message, (list, tuple)) or len(message) != 2:
                continue
            kind, data = message
            if kind == "execution_error":
                return _execution_protocol_error(data)
            if kind == "execution_interrupted":
                return _ComfyCancelled()
    status_str = status.get("status_str")
    if isinstance(status_str, str) and status_str.casefold() in {
        "error",
        "failed",
        "failure",
    }:
        return _ComfyProtocolError("node_runtime_error")
    return None


def _history_succeeded(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    status = entry.get("status")
    if isinstance(status, dict):
        status_str = status.get("status_str")
        if isinstance(status_str, str) and status_str.casefold() in {
            "success",
            "succeeded",
            "completed",
        }:
            return True
        if status.get("completed") is True:
            return True
    outputs = entry.get("outputs")
    return isinstance(outputs, dict) and bool(outputs)


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

    def node_classes(self) -> set[str] | None:
        """Return the currently loaded ComfyUI node classes without node metadata."""

        try:
            response = self._session.get(f"{self._base}/object_info", timeout=120)
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict):
                return None
            return {
                str(name)
                for name, metadata in value.items()
                if isinstance(name, str) and isinstance(metadata, dict)
            }
        except (requests.RequestException, ValueError):
            return None

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
        body: dict[str, Any] | None = None
        try:
            value = response.json()
            if isinstance(value, dict):
                body = value
        except (ValueError, TypeError):
            pass
        if response.status_code >= 400:
            if body is not None and body.get("node_errors"):
                reason, component = _classify_validation_failure(
                    body.get("node_errors"), body.get("error")
                )
                raise _ComfyProtocolError(
                    reason,
                    status_code=response.status_code,
                    component=component,
                )
            raise _ComfyProtocolError("workflow_rejected", status_code=response.status_code)
        try:
            if body is None:
                raise TypeError
            if body.get("node_errors"):
                reason, component = _classify_validation_failure(
                    body.get("node_errors"), body.get("error")
                )
                raise _ComfyProtocolError(reason, component=component)
            return str(body["prompt_id"])
        except (KeyError, TypeError) as exc:
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
                history = self._history(prompt_id)
                history_failure = _history_failure(history)
                if history_failure is not None:
                    raise history_failure
                if _history_succeeded(history):
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
                if raw in ("", b""):
                    logger.warning("ComfyUI websocket closed; falling back to history polling")
                    websocket_closed = True

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
            if not isinstance(message, dict):
                continue
            kind = message.get("type")
            data = message.get("data") or {}
            if not isinstance(data, dict):
                continue
            if data.get("prompt_id") not in (None, prompt_id):
                continue
            if kind == "execution_start":
                stage = "sampling"
            elif kind == "executing":
                if data.get("node") is None and data.get("prompt_id") == prompt_id:
                    on_progress(1.0, "sampled")
                    return
                stage = "processing"
            elif kind == "progress":
                total = data.get("max") or 1
                fraction = min(float(data.get("value", 0)) / float(total), 1.0)
                stage = "sampling"
            elif kind == "execution_error":
                raise _execution_protocol_error(data)
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
        history_failure = _history_failure(entry)
        if history_failure is not None:
            raise history_failure

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
        capability_source: CapabilitySource | None = None,
        model_root: Path | None = None,
        custom_nodes_root: Path | None = None,
        model_verification_progress: Callable[[ModelVerificationProgress], None] | None = None,
    ) -> None:
        self._client = client or ComfyUIClient(base_url)
        self._output_dir = output_dir.expanduser().resolve()
        self._policy = policy
        self._capability_source = capability_source
        self._capability_generation: object = object()
        self._dynamic_capabilities: dict[str, ComfyUIWorkflowCapability] = {}
        self._model_root = (
            model_root.expanduser().resolve()
            if model_root is not None
            else (self._output_dir.parent / "models").resolve()
        )
        self._custom_nodes_root = (
            custom_nodes_root.expanduser().absolute()
            if custom_nodes_root is not None
            else (self._output_dir.parent / "custom_nodes").resolve()
        )
        self._model_digest_cache: dict[Path, tuple[int, int, int, int, int, str]] = {}
        self._model_fingerprint_observations: dict[
            Path,
            tuple[tuple[int, int, int, int, int], int],
        ] = {}
        self._model_resolved_placements: dict[Path, Path] = {}
        self._model_verification_progress = model_verification_progress

    @property
    def execution_policy_configured(self) -> bool:
        self._reload_capabilities()
        return self._policy is not None or bool(self._dynamic_capabilities)

    @property
    def maintenance_custom_nodes_root(self) -> Path:
        return self._custom_nodes_root

    def maintenance_node_classes(self) -> set[str] | None:
        return self._client.node_classes()

    @property
    def maintenance_model_pins(self) -> tuple[ComfyUIModelPin, ...]:
        """Return only locally authorized model pins to the maintenance runtime.

        A Gateway job can select a digest from this tuple, but it cannot supply
        or widen the source, destination, license, or integrity policy.
        """

        capabilities = self._workflow_capabilities()
        pins: dict[tuple[str, str], ComfyUIModelPin] = {}
        if self._policy is not None:
            for pin in self._policy.model_files:
                pins[(pin.path, pin.sha256)] = pin
        for capability in capabilities.values():
            for pin in capability.policy.model_files:
                pins[(pin.path, pin.sha256)] = pin
        return tuple(pins[key] for key in sorted(pins))

    @property
    def maintenance_workflows(self) -> tuple[tuple[str, str], ...]:
        """Exact package-ref to digest bindings allowed to request models."""

        return tuple(
            sorted(
                (capability.workflow_ref, capability.workflow_digest)
                for capability in self._workflow_capabilities().values()
            )
        )

    def workflow_model_pins(
        self, workflow_ref: str, workflow_digest: str
    ) -> tuple[ComfyUIModelPin, ...]:
        capability = self._workflow_capabilities().get(workflow_digest)
        if capability is None or capability.workflow_ref != workflow_ref:
            return ()
        return capability.policy.model_files

    @property
    def maintenance_model_root(self) -> Path:
        """Return the locally selected model root; never sourced from a job."""

        return self._model_root

    def invalidate_model_digest_cache(self) -> None:
        """Force the next capability report to observe newly installed files."""

        self._model_digest_cache.clear()
        self._model_fingerprint_observations.clear()
        self._model_resolved_placements.clear()

    def reload_capabilities(self) -> None:
        """Force an already-running Worker to observe an atomically activated release."""

        self._capability_generation = object()
        self._reload_capabilities()

    def reconcile_workflow_authorizations(
        self, authorizations: Iterable[Mapping[str, Any]]
    ) -> tuple[tuple[str, str], ...]:
        """Atomically deactivate releases absent from the Gateway grant set."""

        reconcile = getattr(self._capability_source, "reconcile_authorizations", None)
        if not callable(reconcile):
            return ()
        removed = tuple(reconcile(authorizations))
        if removed:
            self.reload_capabilities()
        return removed

    def configure_capability_trust(
        self,
        owner_root_signing_public_key: str,
        worker_id: str,
    ) -> None:
        """Give the dynamic source the authenticated local Worker trust anchor."""

        configure = getattr(self._capability_source, "configure_trust", None)
        if callable(configure):
            configure(owner_root_signing_public_key, worker_id)
            self.reload_capabilities()

    def validate_capability_release(self, installed: InstallResult) -> None:
        """Compile a staged release and reject destructive model placements.

        Model bytes are shared machine-wide by ComfyUI.  A workflow therefore
        cannot claim a path that an already-active workflow or the local admin
        policy binds to different immutable bytes.
        """

        candidate = _workflow_capability(installed)
        self._reload_capabilities()
        prospective = dict(self._dynamic_capabilities)
        existing = prospective.get(candidate.workflow_digest)
        if existing is not None and existing.workflow_ref != candidate.workflow_ref:
            raise ComfyUIPolicyError(
                "An active workflow capability digest has conflicting identities."
            )
        prospective[candidate.workflow_digest] = candidate
        if candidate.workflow_digest in _conflicting_model_placement_digests(
            prospective.values(),
            static_policy=self._policy,
        ):
            raise ComfyUIPolicyError(
                "An active workflow capability model path or digest is already bound "
                "to different bytes."
            )

    def descriptor(self) -> ExecutorDescriptor:
        return ExecutorDescriptor(
            executor_type="comfyui",
            version="1.2.0",
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
        capabilities = self._workflow_capabilities()
        (
            verified_custom_nodes,
            custom_node_root_closed,
            node_pack_digests,
            custom_node_provenance_error,
        ) = self._verified_custom_node_state(capabilities.values())
        all_pins = self.maintenance_model_pins
        self._prune_model_digest_state(all_pins)
        verified_model_placements: set[tuple[str, str]] = set()
        model_digests, model_failures = self._verified_model_digests(
            all_pins,
            verified_placements=verified_model_placements,
        )
        gpus, system, vram_bytes, ram_bytes = self._resource_snapshot()
        node_probe = getattr(self._client, "node_classes", None)
        node_classes = node_probe() if callable(node_probe) else None
        runtime_version = system.get("runtime_version")
        workflow_readiness: list[dict[str, Any]] = []
        for capability in sorted(capabilities.values(), key=lambda item: item.workflow_ref):
            # Readiness is placement-aware even though installation and the
            # public aggregate are digest-deduplicated. If the same content is
            # required at two paths, one valid path cannot hide the missing
            # second placement.
            missing_models = sorted(
                {
                    f"sha256:{pin.sha256}"
                    for pin in capability.policy.model_files
                    if (pin.path, pin.sha256) not in verified_model_placements
                }
            )
            required_nodes = (
                capability.policy.allowed_node_classes
                | capability.policy.allowed_custom_node_classes
            )
            missing_nodes = (
                sorted(required_nodes - node_classes)
                if isinstance(node_classes, set)
                else sorted(required_nodes)
            )
            # ComfyUI exposes class names globally, without provider identity.
            # Require every executable root entry to be one of the currently
            # pinned exact checkouts, then require the class to be visible. This
            # is intentionally phrased as two independent facts: true
            # class-to-provider binding needs Node Pack / Host Protocol v2.
            provenance_failures = self._unverified_custom_node_classes(
                capability, verified_custom_nodes
            )
            if not custom_node_root_closed:
                # Any unreviewed executable entry can register or replace a
                # globally named class, including a class otherwise treated as
                # core. Do not let an unrelated workflow remain ready while
                # the shared custom-node import root is outside the closed set.
                provenance_failures.update(required_nodes)
            missing_nodes = sorted(set(missing_nodes) | provenance_failures)
            runtime_compatible = _minimum_version_satisfied(
                runtime_version, capability.runtime_min_version
            )
            executor_compatible = _minimum_version_satisfied(
                self.descriptor().version, capability.executor_min_version
            )
            if not executor_compatible:
                state = "executor_incompatible"
            elif not runtime_compatible:
                state = "runtime_incompatible"
            elif capability.min_vram_bytes is not None and vram_bytes < capability.min_vram_bytes:
                state = "insufficient_vram"
            elif capability.min_ram_bytes is not None and ram_bytes < capability.min_ram_bytes:
                state = "insufficient_ram"
            elif missing_nodes:
                state = "missing_nodes" if node_classes is not None else "node_probe_unavailable"
            elif missing_models:
                state = "missing_models"
            else:
                state = "ready"
            readiness_entry: dict[str, Any] = {
                "workflow_ref": capability.workflow_ref,
                "workflow_digest": capability.workflow_digest,
                "state": state,
                "missing_model_digests": missing_models,
                "missing_node_classes": missing_nodes,
            }
            if custom_node_provenance_error is not None:
                readiness_entry["custom_node_provenance_error"] = custom_node_provenance_error
            workflow_readiness.append(readiness_entry)
        return {
            "executor_type": "comfyui",
            "payload_formats": [COMFYUI_PAYLOAD_FORMAT],
            "model_digests": model_digests,
            "node_pack_digests": sorted(f"sha256:{item}" for item in node_pack_digests),
            "capability_schema_version": 2,
            "ready_workflow_digests": [
                item["workflow_digest"] for item in workflow_readiness if item["state"] == "ready"
            ],
            "workflow_readiness": workflow_readiness,
            "gpus": gpus,
            "vram_bytes": vram_bytes,
            "ram_bytes": ram_bytes,
            "runtime_version": system.get("runtime_version"),
            "system": system,
            "execution_policy": {
                "configured": self.execution_policy_configured,
                "model_pins": len(all_pins),
                "models_verified": len(model_digests),
                "models_failed": model_failures,
            },
        }

    def _unverified_custom_node_classes(
        self,
        capability: ComfyUIWorkflowCapability,
        verified: set[tuple[str, str]],
    ) -> set[str]:
        pinned_node_types = {
            node_type
            for dependency in capability.custom_nodes
            for node_type in dependency.node_types
        }
        return set(capability.policy.allowed_custom_node_classes - pinned_node_types) | {
            node_type
            for dependency in capability.custom_nodes
            if (dependency.source, dependency.revision) not in verified
            for node_type in dependency.node_types
        }

    def _verified_custom_node_state(
        self,
        capabilities: Iterable[ComfyUIWorkflowCapability],
    ) -> tuple[set[tuple[str, str]], bool, set[str], str | None]:
        dependencies = {
            dependency for capability in capabilities for dependency in capability.custom_nodes
        }
        root = self._custom_nodes_root
        try:
            root.lstat()
        except FileNotFoundError:
            closed = not dependencies
            return set(), closed, set(), None if closed else "root_missing"
        except OSError:
            return set(), False, set(), "root_unavailable"
        if _is_reparse_point(root):
            return set(), False, set(), "root_unsafe"
        if not root.is_dir():
            closed = not dependencies
            return set(), closed, set(), None if closed else "root_not_directory"
        try:
            # A symlink/junction in any root ancestor changes the code tree
            # after configuration. The isolated root must resolve to itself.
            if root.resolve(strict=True) != root:
                return set(), False, set(), "root_unsafe"
        except (OSError, RuntimeError):
            return set(), False, set(), "root_unavailable"

        expected = {(dependency.source, dependency.revision) for dependency in dependencies}
        # One heartbeat has a strict global probe budget. An oversized policy
        # or directory fails closed instead of multiplying Git processes or
        # making root enumeration an unbounded operation.
        if len(dependencies) > 32 or len(expected) > 32:
            return set(), False, set(), "provider_limit_exceeded"
        repositories: list[Path] = []
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if len(repositories) >= 32:
                        return set(), False, set(), "provider_limit_exceeded"
                    repository = root / entry.name
                    if _is_reparse_point(repository) or not entry.is_dir(follow_symlinks=False):
                        # ComfyUI can import top-level Python files as custom
                        # nodes. Unknown files, links and non-repository
                        # directories are therefore executable attack surface,
                        # not harmless metadata.
                        return (
                            set(),
                            False,
                            set(),
                            _provenance_error("unexpected_entry", entry.name),
                        )
                    repositories.append(repository)
        except OSError:
            return set(), False, set(), "root_unavailable"

        # Git verification uses several short-lived subprocesses per reviewed
        # checkout. A fixed five-second budget was enough for two providers on
        # fast disks, but adding one managed Node Pack made clean Windows roots
        # fail closed purely from process-startup latency. Scale the shared
        # budget with the bounded root size while retaining a hard heartbeat
        # ceiling for unexpectedly large roots.
        probe_budget = _custom_node_probe_budget(len(repositories))
        deadline = time.monotonic() + probe_budget
        verified: set[tuple[str, str]] = set()
        node_pack_digests: set[str] = set()
        for repository in sorted(repositories, key=lambda item: str(item).casefold()):
            managed_identity = self._verified_node_pack_repository(
                repository,
                dependencies=dependencies,
                deadline=deadline,
            )
            if managed_identity is None:
                identity = self._verified_custom_node_repository(repository, deadline=deadline)
            else:
                identity = managed_identity[:2]
                node_pack_digests.add(managed_identity[2])
            if identity is None:
                return (
                    set(),
                    False,
                    set(),
                    _provenance_error("provider_unverified", repository.name),
                )
            matching_expected = {
                expected_identity
                for expected_identity in expected
                if expected_identity[1] == identity[1]
                and _canonical_git_source(expected_identity[0])
                == _canonical_git_source(identity[0])
            }
            if len(matching_expected) != 1:
                same_source = any(
                    _canonical_git_source(expected_identity[0])
                    == _canonical_git_source(identity[0])
                    for expected_identity in expected
                )
                same_revision = any(
                    expected_identity[1] == identity[1] for expected_identity in expected
                )
                reason = (
                    "provider_revision_mismatch"
                    if same_source
                    else "provider_source_mismatch"
                    if same_revision
                    else "provider_identity_mismatch"
                )
                return (
                    set(),
                    False,
                    set(),
                    _provenance_error(reason, repository.name),
                )
            verified_identity = next(iter(matching_expected))
            if verified_identity in verified:
                return set(), False, set(), "provider_duplicate"
            verified.add(verified_identity)
        closed = verified == expected
        return (
            verified,
            closed,
            node_pack_digests,
            None if closed else "provider_missing",
        )

    @staticmethod
    def _verified_node_pack_repository(
        repository: Path,
        *,
        dependencies: set[ComfyUICustomNodePin],
        deadline: float,
    ) -> tuple[str, str, str] | None:
        """Verify every activated byte against a Worker-generated Node Pack receipt."""

        marker = repository / ".vgen-node-pack.json"
        if _is_reparse_point(repository) or _is_reparse_point(marker):
            return None
        try:
            marker_metadata = marker.lstat()
            if (
                not stat.S_ISREG(marker_metadata.st_mode)
                or marker_metadata.st_size <= 0
                or marker_metadata.st_size > 2 * 1024 * 1024
            ):
                return None
            value = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            return None
        if not isinstance(value, dict) or set(value) != {
            "format",
            "version",
            "node_pack_id",
            "node_pack_version",
            "artifact_sha256",
            "source",
            "revision",
            "node_classes",
            "files",
        }:
            return None
        node_pack_id = value.get("node_pack_id")
        node_pack_version = value.get("node_pack_version")
        artifact_sha256 = value.get("artifact_sha256")
        source = value.get("source")
        revision = value.get("revision")
        node_classes = value.get("node_classes")
        files = value.get("files")
        if (
            value.get("format") != "vgen-node-pack-activation"
            or value.get("version") != 1
            or not isinstance(node_pack_id, str)
            or not isinstance(node_pack_version, str)
            or not isinstance(artifact_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", artifact_sha256) is None
            or not isinstance(source, str)
            or not isinstance(revision, str)
            or not isinstance(node_classes, list)
            or any(not isinstance(item, str) for item in node_classes)
            or not isinstance(files, list)
            or not 1 <= len(files) <= 8192
        ):
            return None
        node_pack_ref = f"{node_pack_id}@{node_pack_version}"
        matching = [
            dependency
            for dependency in dependencies
            if dependency.node_pack == node_pack_ref
            and dependency.node_pack_sha256 == artifact_sha256
            and dependency.source == source
            and dependency.revision == revision
        ]
        provided_node_classes = frozenset(node_classes)
        if not matching or any(
            not dependency.node_types.issubset(provided_node_classes) for dependency in matching
        ):
            # A reviewed Node Pack may expose more classes than one workflow
            # uses. The immutable artifact digest binds that complete provider;
            # each workflow still authorizes only its declared subset.
            return None

        declared: dict[str, tuple[int, str]] = {}
        for item in files:
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
                return None
            raw_path = item.get("path")
            digest = item.get("sha256")
            size = item.get("size")
            if (
                not isinstance(raw_path, str)
                or len(raw_path) > 512
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or type(size) is not int
                or size < 0
            ):
                return None
            try:
                canonical = canonical_package_path(raw_path, label="Node Pack active file")
                key = package_path_key(canonical)
            except ValueError:
                return None
            if canonical != raw_path or key in declared or key == ".vgen-node-pack.json":
                return None
            declared[key] = (size, digest)

        observed: set[str] = set()
        try:
            for path in repository.rglob("*"):
                if time.monotonic() >= deadline:
                    return None
                relative = path.relative_to(repository).as_posix()
                if relative == ".vgen-node-pack.json":
                    continue
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode) and not path.is_symlink():
                    continue
                if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(path):
                    return None
                key = package_path_key(relative)
                expected_file = declared.get(key)
                if expected_file is None or metadata.st_size != expected_file[0]:
                    return None
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                        if time.monotonic() >= deadline:
                            return None
                if digest.hexdigest() != expected_file[1]:
                    return None
                observed.add(key)
        except (OSError, ValueError):
            return None
        if observed != set(declared):
            return None
        return source, revision, artifact_sha256

    @staticmethod
    def _verified_custom_node_repository(
        repository: Path, *, deadline: float
    ) -> tuple[str, str] | None:
        # This is a bounded attestation of the current on-disk checkout. It is
        # not an isolation boundary against the same OS user changing files
        # after this probe; Worker deployment must still restrict that user.
        if _is_reparse_point(repository) or not repository.is_dir():
            return None
        try:
            repository = repository.resolve(strict=True)
        except OSError:
            return None
        git_directory = repository / ".git"
        if (
            not git_directory.is_dir()
            or _is_reparse_point(git_directory)
            or git_directory.resolve() != git_directory
        ):
            return None
        git_location = shutil.which("git")
        if not git_location or not Path(git_location).is_absolute():
            return None
        try:
            git_executable = Path(git_location).resolve(strict=True)
            git_metadata = git_executable.lstat()
        except OSError:
            return None
        if not stat.S_ISREG(git_metadata.st_mode) or _is_reparse_point(git_executable):
            return None
        git_environment = {
            key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")
        }
        git_environment["GIT_OPTIONAL_LOCKS"] = "0"

        def git(*arguments: str, raw: bool = False) -> str | None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            process: subprocess.Popen[bytes] | None = None
            output = bytearray()
            overflow = threading.Event()

            def read_bounded() -> None:
                if process is None or process.stdout is None:
                    overflow.set()
                    return
                while True:
                    block = process.stdout.read(4096)
                    if not block:
                        return
                    if len(output) + len(block) > 16_384:
                        overflow.set()
                        process.kill()
                        return
                    output.extend(block)

            try:
                process = subprocess.Popen(  # noqa: S603 - fixed local Git executable
                    [
                        str(git_executable),
                        "-c",
                        f"core.hooksPath={'NUL' if os.name == 'nt' else '/dev/null'}",
                        "-c",
                        "core.fsmonitor=false",
                        "-C",
                        str(repository),
                        *arguments,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=git_environment,
                )
                reader = threading.Thread(target=read_bounded, daemon=True)
                reader.start()
                try:
                    return_code = process.wait(timeout=min(1.5, remaining))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                    return None
                reader.join(timeout=2)
                if reader.is_alive():
                    process.kill()
                    return None
            except (OSError, subprocess.SubprocessError):
                if process is not None:
                    process.kill()
                return None
            if return_code != 0 or overflow.is_set():
                return None
            try:
                decoded = output.decode("utf-8", errors="strict")
            except UnicodeError:
                return None
            return decoded if raw else decoded.strip()

        source = git("remote", "get-url", "origin")
        if source is None:
            return None
        top_level = git("rev-parse", "--show-toplevel")
        if top_level is None:
            return None
        absolute_git_directory = git("rev-parse", "--absolute-git-dir")
        if absolute_git_directory is None:
            return None
        try:
            if Path(top_level).resolve(strict=True) != repository:
                return None
            if Path(absolute_git_directory).resolve(strict=True) != git_directory:
                return None
        except OSError:
            return None
        revision = git("rev-parse", "--verify", "HEAD^{commit}")
        if revision is None:
            return None
        index_flags = git("ls-files", "-v", "-z", raw=True)
        if index_flags is None:
            return None
        flag_records = [record for record in index_flags.split("\x00") if record]
        if any(not record.startswith("H ") for record in flag_records):
            # Reject skip-worktree, assume-unchanged and non-cached entries;
            # all can hide bytes from an otherwise clean status result.
            return None
        staged = git("ls-files", "--stage", "-z", raw=True)
        if staged is None:
            return None
        for record in (item for item in staged.split("\x00") if item):
            metadata, separator, raw_path = record.partition("\t")
            fields = metadata.split(" ")
            if (
                separator != "\t"
                or len(fields) != 3
                or fields[0] not in {"100644", "100755"}
                or fields[2] != "0"
                or not raw_path
                or "\\" in raw_path
            ):
                # In particular, reject tracked symlinks (120000) and
                # submodules/gitlinks (160000).
                return None
            relative = PurePosixPath(raw_path)
            if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                return None
            current = repository
            for part in relative.parts:
                current /= part
                if _is_reparse_point(current):
                    return None
            try:
                if not stat.S_ISREG(current.lstat().st_mode):
                    return None
            except OSError:
                return None
        status = git(
            "status",
            "--ignored=matching",
            "--porcelain=v1",
            "--untracked-files=all",
        )
        if not source or not revision or status is None or status:
            return None
        if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            return None
        return source, revision

    def _resource_snapshot(self) -> tuple[list[dict[str, Any]], dict[str, Any], int, int]:
        gpus = self._client.gpu_info()
        system_info = getattr(self._client, "system_info", None)
        system = system_info() if callable(system_info) else {}
        if not isinstance(system, dict):
            system = {}
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
        raw_ram_bytes = system.get("ram_bytes")
        ram_bytes = (
            raw_ram_bytes
            if isinstance(raw_ram_bytes, int) and not isinstance(raw_ram_bytes, bool)
            else 0
        )
        return gpus, system, vram_bytes, max(0, ram_bytes)

    def _verified_model_digests(
        self,
        pins: tuple[ComfyUIModelPin, ...],
        *,
        verified_placements: set[tuple[str, str]] | None = None,
    ) -> tuple[list[str], int]:
        verified: list[str] = []
        failures = 0
        total_size = sum(pin.size for pin in pins)
        total_bytes_read = 0
        last_reported_total_percent = -1
        cache_now_ns = time.time_ns()
        observation_now_ns = time.monotonic_ns()
        fingerprint_digests: dict[tuple[int, int, int, int, int], str] = {}

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
            total_percent = 100 if total_size == 0 else int(total_bytes_read * 100 / total_size)
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
            unresolved = (self._model_root / pin.path).absolute()
            try:
                candidate = unresolved.resolve()
            except (OSError, RuntimeError):
                self._forget_model_placement(unresolved)
                failures += 1
                continue
            if self._model_root != candidate and self._model_root not in candidate.parents:
                self._forget_model_placement(unresolved, candidate)
                failures += 1
                continue
            self._remember_model_placement(unresolved, candidate)
            try:
                metadata = candidate.stat()
            except OSError:
                self._forget_model_placement(unresolved, candidate)
                failures += 1
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != pin.size:
                self._forget_model_placement(unresolved, candidate)
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
            observation = self._model_fingerprint_observations.get(candidate)
            if observation is None or observation[0] != fingerprint:
                observation = (fingerprint, observation_now_ns)
                self._model_fingerprint_observations[candidate] = observation
                self._model_digest_cache.pop(candidate, None)
                cached = None
            observation_age_ns = max(0, observation_now_ns - observation[1])
            metadata_age_ns = cache_now_ns - max(
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            cache_identity_is_stable = (
                metadata_age_ns >= _MODEL_DIGEST_CACHE_SETTLE_NS
                or observation_age_ns >= _MODEL_DIGEST_CACHE_SETTLE_NS
            )
            if cached is not None and (cached[:5] != fingerprint or not cache_identity_is_stable):
                # Never let a digest recorded for a fresh or superseded stat
                # identity become trusted merely because wall time advanced.
                self._model_digest_cache.pop(candidate, None)
                cached = None
            if cached is not None and cached[:5] == fingerprint and cache_identity_is_stable:
                digest = cached[5]
                if metadata.st_ino != 0:
                    fingerprint_digests[fingerprint] = digest
                total_bytes_read += pin.size
                report(
                    model_index=model_index,
                    pin=pin,
                    file_bytes_read=pin.size,
                    force=True,
                )
            elif fingerprint in fingerprint_digests:
                # ModelInstaller materializes one verified CAS blob through
                # hard links. Reuse the digest for the same immutable file
                # identity instead of rereading tens of gigabytes per placement.
                # Only identities that were already settled when this probe
                # started enter the map, and inode zero is never treated as a
                # portable hard-link identity.
                digest = fingerprint_digests[fingerprint]
                self._model_digest_cache[candidate] = (*fingerprint, digest)
                total_bytes_read += pin.size
                report(
                    model_index=model_index,
                    pin=pin,
                    file_bytes_read=pin.size,
                    force=True,
                )
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
                    self._forget_model_placement(unresolved, candidate)
                    failures += 1
                    continue
                digest = hasher.hexdigest()
                report(
                    model_index=model_index,
                    pin=pin,
                    file_bytes_read=file_bytes_read,
                    force=True,
                )
                try:
                    after = candidate.stat()
                except OSError:
                    self._forget_model_placement(unresolved, candidate)
                    failures += 1
                    continue
                if (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ) != fingerprint:
                    self._forget_model_placement(unresolved, candidate)
                    failures += 1
                    continue
                if cache_identity_is_stable:
                    self._model_digest_cache[candidate] = (*fingerprint, digest)
                    if metadata.st_ino != 0:
                        fingerprint_digests[fingerprint] = digest
            if digest != pin.sha256:
                failures += 1
                continue
            if verified_placements is not None:
                verified_placements.add((pin.path, pin.sha256))
            verified.append(f"sha256:{digest}")
        return sorted(set(verified)), failures

    def _forget_model_digest_state(self, candidate: Path) -> None:
        self._model_digest_cache.pop(candidate, None)
        self._model_fingerprint_observations.pop(candidate, None)

    def _remember_model_placement(self, unresolved: Path, candidate: Path) -> None:
        previous = self._model_resolved_placements.get(unresolved)
        if previous is not None and previous != candidate:
            self._forget_model_digest_state(previous)
        self._model_resolved_placements[unresolved] = candidate

    def _forget_model_placement(
        self,
        unresolved: Path,
        candidate: Path | None = None,
    ) -> None:
        previous = self._model_resolved_placements.pop(unresolved, None)
        for resolved in {unresolved, previous, candidate} - {None}:
            self._forget_model_digest_state(resolved)

    def _prune_model_digest_state(self, pins: tuple[ComfyUIModelPin, ...]) -> None:
        active: set[Path] = set()
        active_placements: set[Path] = set()
        for pin in pins:
            unresolved = (self._model_root / pin.path).absolute()
            try:
                candidate = unresolved.resolve()
            except (OSError, RuntimeError):
                self._forget_model_placement(unresolved)
                continue
            if candidate == self._model_root or self._model_root in candidate.parents:
                self._remember_model_placement(unresolved, candidate)
                active_placements.add(unresolved)
                active.add(candidate)
            else:
                self._forget_model_placement(unresolved, candidate)
        for unresolved in self._model_resolved_placements.keys() - active_placements:
            self._forget_model_placement(unresolved)
        for state in (
            self._model_digest_cache,
            self._model_fingerprint_observations,
        ):
            for candidate in state.keys() - active:
                state.pop(candidate, None)

    def _reload_capabilities(self) -> None:
        if self._capability_source is None:
            return
        try:
            generation = self._capability_source.generation()
        except Exception as exc:
            logger.error(
                "Ignoring unavailable dynamic workflow capability index: %s",
                type(exc).__name__,
            )
            self._dynamic_capabilities = {}
            self._capability_generation = object()
            return
        if generation == self._capability_generation:
            return
        loaded: dict[str, ComfyUIWorkflowCapability] = {}
        invalid_digests: set[str] = set()
        had_errors = False
        try:
            active = self._capability_source.active()
        except Exception as exc:
            logger.error(
                "Ignoring unavailable dynamic workflow capability releases: %s",
                type(exc).__name__,
            )
            self._dynamic_capabilities = {}
            self._capability_generation = object()
            return
        for installed in active:
            try:
                capability = _workflow_capability(installed)
            except Exception as exc:
                had_errors = True
                logger.error(
                    "Ignoring invalid dynamic workflow capability release: %s",
                    type(exc).__name__,
                )
                continue
            if capability.workflow_digest in invalid_digests:
                continue
            previous = loaded.get(capability.workflow_digest)
            if previous is not None and previous.workflow_ref != capability.workflow_ref:
                had_errors = True
                loaded.pop(capability.workflow_digest, None)
                invalid_digests.add(capability.workflow_digest)
                logger.error("Ignoring conflicting dynamic workflow capability digest.")
                continue
            loaded[capability.workflow_digest] = capability
        had_errors = had_errors or bool(getattr(self._capability_source, "active_errors", 0))
        conflicting_digests = _conflicting_model_placement_digests(
            loaded.values(),
            static_policy=self._policy,
        )
        if conflicting_digests:
            had_errors = True
            for digest in conflicting_digests:
                loaded.pop(digest, None)
            logger.error(
                "Ignoring dynamic workflow capabilities with conflicting model placements."
            )
        self._dynamic_capabilities = loaded
        # Keep retrying a partially invalid generation so an administrator can
        # repair one release without rewriting active.json. Healthy releases
        # remain available throughout the repair.
        self._capability_generation = object() if had_errors else generation

    def _workflow_capabilities(self) -> dict[str, ComfyUIWorkflowCapability]:
        self._reload_capabilities()
        values: dict[str, ComfyUIWorkflowCapability] = {}
        if self._policy is not None:
            for workflow_ref, workflow_digest in self._policy.maintenance_workflows:
                values[workflow_digest] = ComfyUIWorkflowCapability(
                    workflow_ref,
                    workflow_digest,
                    self._policy,
                    custom_nodes=self._policy.custom_nodes,
                )
        for digest, capability in self._dynamic_capabilities.items():
            existing = values.get(digest)
            # A legacy machine-admin policy remains authoritative for the same
            # exact release (notably H3, whose market manifest intentionally
            # marks model downloads as manual metadata). The activated package
            # still contributes its exact operation/graph/parameter binding.
            if existing is None:
                values[digest] = capability
            elif existing.workflow_ref == capability.workflow_ref:
                values[digest] = ComfyUIWorkflowCapability(
                    workflow_ref=capability.workflow_ref,
                    workflow_digest=capability.workflow_digest,
                    policy=existing.policy,
                    executor_min_version=capability.executor_min_version,
                    runtime_min_version=capability.runtime_min_version,
                    operations=capability.operations,
                    template_graph=capability.template_graph,
                    mapping=capability.mapping,
                    parameter_schema=capability.parameter_schema,
                    min_vram_bytes=capability.min_vram_bytes,
                    min_ram_bytes=capability.min_ram_bytes,
                    custom_nodes=tuple(
                        dict.fromkeys((*existing.custom_nodes, *capability.custom_nodes))
                    ),
                )
        return values

    def _capability_for_digest(self, workflow_digest: str) -> ComfyUIWorkflowCapability | None:
        capability = self._workflow_capabilities().get(workflow_digest)
        if capability is not None:
            return capability
        if self._policy is None:
            return None
        try:
            self._policy.authorize_digest(workflow_digest)
        except ExecutorFailure:
            return None
        return ComfyUIWorkflowCapability("", workflow_digest, self._policy)

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
        capability = self._capability_for_digest(request.workflow_digest)
        policy = capability.policy if capability is not None else None
        if (
            capability is not None
            and capability.template_graph is not None
            and request.operation not in capability.operations
        ):
            raise _policy_denied("operation_not_allowed_by_workflow")
        if capability is not None and (
            capability.min_vram_bytes is not None or capability.min_ram_bytes is not None
        ):
            _gpus, _system, vram_bytes, ram_bytes = self._resource_snapshot()
            if capability.min_vram_bytes is not None and vram_bytes < capability.min_vram_bytes:
                raise ExecutorFailure(
                    ErrorCode.GPU_OUT_OF_MEMORY,
                    "GPU_OUT_OF_MEMORY",
                    "This Worker does not meet the workflow GPU-memory requirement.",
                    retry_action=RetryAction.ANOTHER_WORKER,
                    details={"reason": "insufficient_vram"},
                )
            if capability.min_ram_bytes is not None and ram_bytes < capability.min_ram_bytes:
                raise ExecutorFailure(
                    ErrorCode.SYSTEM_OUT_OF_MEMORY,
                    "SYSTEM_OUT_OF_MEMORY",
                    "This Worker does not meet the workflow system-memory requirement.",
                    retry_action=RetryAction.ANOTHER_WORKER,
                    details={"reason": "insufficient_ram"},
                )
        if policy is not None and policy.model_files:
            verified_models, model_failures = self._verified_model_digests(policy.model_files)
            required_model_digests = {pin.sha256 for pin in policy.model_files}
            if model_failures or len(verified_models) != len(required_model_digests):
                raise ExecutorFailure(
                    ErrorCode.DEPENDENCY_MISSING,
                    "DEPENDENCY_MISSING",
                    "A locally pinned ComfyUI model is missing or failed integrity verification.",
                    details={"reason": "model_integrity_unavailable"},
                )

        if policy is None:
            raise _provider_environment_failure(
                "policy_required",
                "The ComfyUI executor has no local workflow policy configured.",
            )
        policy.authorize_digest(request.workflow_digest)
        if len(request.payload) > policy.max_payload_bytes:
            raise _policy_denied("payload_size_limit")
        workflow, bindings, parameters = self._decode_payload(request.payload)
        policy.authorize_graph(workflow, bindings)
        if capability is not None and capability.template_graph is not None:
            self._authorize_capability_payload(
                capability,
                request.operation,
                workflow,
                bindings,
                parameters,
            )
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
        except MemoryError as exc:
            raise ExecutorFailure(
                ErrorCode.SYSTEM_OUT_OF_MEMORY,
                "SYSTEM_OUT_OF_MEMORY",
                "ComfyUI ran out of system memory.",
                retry_action=RetryAction.ANOTHER_WORKER,
                details={"reason": "system_out_of_memory"},
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
    def _decode_payload(
        payload: bytes,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any] | None]:
        try:
            body = json.loads(payload.decode("utf-8"))
            if not isinstance(body, dict) or set(body) - {
                "workflow",
                "input_bindings",
                "effective_parameters",
            }:
                raise TypeError
            workflow = body["workflow"]
            bindings = body.get("input_bindings") or []
            parameters = body.get("effective_parameters")
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
        if parameters is not None and not isinstance(parameters, dict):
            raise ExecutorFailure(
                ErrorCode.UNSUPPORTED_PAYLOAD,
                "UNSUPPORTED_PAYLOAD",
                "ComfyUI effective parameters must be an object.",
            )
        return workflow, bindings, parameters

    @staticmethod
    def _authorize_capability_payload(
        capability: ComfyUIWorkflowCapability,
        operation: str,
        workflow: dict[str, Any],
        bindings: list[dict[str, Any]],
        parameters: dict[str, Any] | None,
    ) -> None:
        template = capability.template_graph
        mapping = capability.mapping
        schema = capability.parameter_schema
        if template is None or mapping is None or schema is None or parameters is None:
            raise _policy_denied("workflow_parameters_required")
        validator = Draft202012Validator(schema)
        if next(validator.iter_errors(parameters), None) is not None:
            raise _policy_denied("workflow_parameters_invalid")
        try:
            expected_graph, effective, derived_operation = build_comfy_graph(
                template, mapping, parameters
            )
        except WorkflowBuildError as exc:
            raise _policy_denied("workflow_mapping_invalid") from exc
        if effective != parameters:
            raise _policy_denied("workflow_parameters_not_canonical")
        if derived_operation != operation:
            raise _policy_denied("workflow_operation_mismatch")
        if expected_graph != workflow:
            raise _policy_denied("workflow_graph_mismatch")
        expected_bindings = _capability_expected_bindings(expected_graph, mapping, effective)
        if _normalized_bindings(workflow, bindings) != _normalized_bindings(
            expected_graph, expected_bindings
        ):
            raise _policy_denied("workflow_bindings_mismatch")

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
            raise _provider_environment_failure(
                "output_path_outside_root",
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
        reason = error.reason
        details = error.safe_details()
        if reason == "gpu_out_of_memory":
            return ExecutorFailure(
                ErrorCode.GPU_OUT_OF_MEMORY,
                "GPU_OUT_OF_MEMORY",
                "ComfyUI ran out of GPU memory.",
                retry_action=RetryAction.ANOTHER_WORKER,
                details=details,
            )
        if reason == "system_out_of_memory":
            return ExecutorFailure(
                ErrorCode.SYSTEM_OUT_OF_MEMORY,
                "SYSTEM_OUT_OF_MEMORY",
                "ComfyUI ran out of system memory.",
                retry_action=RetryAction.ANOTHER_WORKER,
                details=details,
            )
        if reason in {"no_output", "history_missing"}:
            return ExecutorFailure(
                ErrorCode.DEPENDENCY_MISSING,
                "DEPENDENCY_MISSING",
                "ComfyUI did not produce an accessible output artifact.",
                retry_action=RetryAction.SAME_WORKER,
                details=details,
            )
        return ExecutorFailure(
            ErrorCode.DEPENDENCY_MISSING,
            "DEPENDENCY_MISSING",
            "ComfyUI execution failed because its local environment is incomplete.",
            retry_action=RetryAction.SAME_WORKER,
            details=details,
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
