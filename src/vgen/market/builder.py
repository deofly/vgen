from __future__ import annotations

import copy
import json
import random
from pathlib import Path
from typing import Any


class WorkflowBuildError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowBuildError(f"cannot read workflow JSON: {exc}") from exc
    if not isinstance(value, dict) or not value or "nodes" in value:
        raise WorkflowBuildError("workflow must be a ComfyUI API-format graph")
    return value


def build_comfy_graph(
    template: dict[str, Any], mapping: dict[str, Any], parameters: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str]:
    graph = copy.deepcopy(template)
    effective = dict(parameters)
    if "seed" in mapping and (effective.get("seed") is None or int(effective["seed"]) < 0):
        effective["seed"] = random.SystemRandom().randint(0, 2**32 - 1)
    unknown = sorted(set(effective) - set(mapping))
    if unknown:
        raise WorkflowBuildError(f"workflow does not map parameters: {unknown}")
    for name, value in effective.items():
        if value is None:
            continue
        rule = mapping[name]
        node_id, node = _find_node(graph, rule, name)
        field = _find_input(node, rule, name)
        if isinstance(node["inputs"][field], list):
            raise WorkflowBuildError(f"{name} targets a connected input")
        node["inputs"][field] = _coerce(node["inputs"][field], value, name)
    for optional in ("image", "last_image"):
        if optional in mapping and not effective.get(optional):
            _remove_optional(graph, mapping[optional], optional)
    operation = "flf" if effective.get("last_image") else "i2v" if effective.get("image") else "t2v"
    if operation == "flf" and not effective.get("image"):
        raise WorkflowBuildError("last_image requires image")
    return graph, effective, operation


def _find_node(
    graph: dict[str, Any], rule: dict[str, Any], parameter: str
) -> tuple[str, dict[str, Any]]:
    if rule.get("node") is not None:
        node_id = str(rule["node"])
        if node_id not in graph:
            raise WorkflowBuildError(f"{parameter} node {node_id} does not exist")
        return node_id, graph[node_id]
    title = rule.get("title")
    matches = [
        (node_id, node)
        for node_id, node in graph.items()
        if isinstance(node, dict) and (node.get("_meta") or {}).get("title") == title
    ]
    if len(matches) != 1:
        raise WorkflowBuildError(f"{parameter} expected one node titled {title!r}")
    return matches[0]


def _find_input(node: dict[str, Any], rule: dict[str, Any], parameter: str) -> str:
    candidates = rule.get("input")
    candidates = [candidates] if isinstance(candidates, str) else candidates or []
    for candidate in candidates:
        if candidate in (node.get("inputs") or {}):
            return candidate
    raise WorkflowBuildError(f"{parameter} has no matching input in the selected node")


def _remove_optional(graph: dict[str, Any], rule: dict[str, Any], parameter: str) -> None:
    connection = rule.get("optional_connection")
    if not connection:
        return
    source_id, _ = _find_node(graph, rule, parameter)
    target_rule = {
        key: value
        for key, value in {
            "title": connection.get("target_title"),
            "node": connection.get("target_node"),
        }.items()
        if value is not None
    }
    _, target = _find_node(graph, target_rule, parameter)
    input_name = connection.get("input")
    expected = [source_id, int(connection.get("output", 0))]
    if (target.get("inputs") or {}).get(input_name) != expected:
        raise WorkflowBuildError(f"{parameter} optional connection does not match its mapping")
    target["inputs"].pop(input_name)
    graph.pop(source_id)


def _coerce(current: Any, value: Any, parameter: str) -> Any:
    try:
        if isinstance(current, bool):
            return bool(value)
        if isinstance(current, int):
            return int(value)
        if isinstance(current, float):
            return float(value)
        return value
    except (TypeError, ValueError) as exc:
        raise WorkflowBuildError(f"cannot coerce {parameter}: {value!r}") from exc
