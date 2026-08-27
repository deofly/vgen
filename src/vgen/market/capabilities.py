"""Deterministic facts bound into a remotely activated workflow capability."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vgen.crypto import canonical_json

from .builder import load_json
from .models import WorkflowManifest, WorkflowVariant


class WorkflowCapabilityError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ComfyUICapabilityFacts:
    variant: WorkflowVariant
    graph: dict[str, Any]
    mapping: dict[str, Any]
    node_classes: frozenset[str]
    node_classes_digest: str


def comfyui_capability_facts(
    manifest: WorkflowManifest,
    directory: Path,
) -> ComfyUICapabilityFacts:
    variants = [variant for variant in manifest.variants if variant.executor_type == "comfyui"]
    if len(variants) != 1 or variants[0].payload_format != "comfyui-api-graph/v1":
        raise WorkflowCapabilityError("workflow needs exactly one ComfyUI API graph variant")
    variant = variants[0]
    try:
        graph = load_json(directory / variant.payload)
    except ValueError as exc:
        raise WorkflowCapabilityError("workflow capability graph is invalid") from exc
    if variant.mapping is None:
        mapping: dict[str, Any] = {}
    else:
        try:
            raw_mapping = json.loads((directory / variant.mapping).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise WorkflowCapabilityError("workflow capability mapping is invalid") from exc
        if not isinstance(raw_mapping, dict) or not all(
            isinstance(name, str) and isinstance(rule, dict) for name, rule in raw_mapping.items()
        ):
            raise WorkflowCapabilityError("workflow capability mapping is invalid")
        mapping = raw_mapping
    node_classes = frozenset(
        node["class_type"]
        for node in graph.values()
        if isinstance(node, dict) and isinstance(node.get("class_type"), str)
    )
    if not node_classes:
        raise WorkflowCapabilityError("workflow capability graph has no nodes")
    digest = hashlib.sha256(canonical_json(sorted(node_classes))).hexdigest()
    return ComfyUICapabilityFacts(variant, graph, mapping, node_classes, digest)


def workflow_model_digests(variant: WorkflowVariant) -> tuple[str, ...]:
    """Return each immutable model blob once, independent of its placements."""

    return tuple(
        sorted({"sha256:" + model.sha256.removeprefix("sha256:") for model in variant.models})
    )


__all__ = [
    "ComfyUICapabilityFacts",
    "WorkflowCapabilityError",
    "comfyui_capability_facts",
    "workflow_model_digests",
]
