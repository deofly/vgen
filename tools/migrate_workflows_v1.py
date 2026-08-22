#!/usr/bin/env python3
"""Convert legacy VGen ComfyUI JSON files into unsigned v1 custom packages.

The command is intentionally dry-run by default. It only scans direct
``*.json`` children of the selected workflow directory and never opens the
legacy task database, task history, tokens, artifacts, or output directories.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from vgen.market.builder import WorkflowBuildError, build_comfy_graph
from vgen.market.models import WorkflowManifest
from vgen.market.registry import (
    WorkflowRegistry,
    package_digest,
    validate_package,
    write_checksums,
)

SAFE_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# This is the exact fallback convention used by the legacy CLI when no
# <name>.map.json file existed. The migration materializes it so the v1 package
# has no hidden dependency on legacy source code.
LEGACY_DEFAULT_MAPPING: dict[str, dict[str, Any]] = {
    "prompt": {"title": "POSITIVE_PROMPT", "input": "text"},
    "negative_prompt": {"title": "NEGATIVE_PROMPT", "input": "text"},
    "seed": {"title": "SAMPLER", "input": ["noise_seed", "seed"]},
    "steps": {"title": "SAMPLER", "input": "steps"},
    "cfg": {"title": "SAMPLER", "input": "cfg"},
    "width": {"title": "LATENT", "input": "width"},
    "height": {"title": "LATENT", "input": "height"},
    "frames": {"title": "LATENT", "input": ["length", "batch_size", "num_frames"]},
    "fps": {"title": "VIDEO_OUTPUT", "input": ["fps", "frame_rate"]},
    "image": {"title": "INPUT_IMAGE", "input": "image"},
    "last_image": {"title": "LAST_IMAGE", "input": "image"},
}

PARAMETER_TYPES = {
    "prompt": "string",
    "negative_prompt": "string",
    "seed": "integer",
    "steps": "integer",
    "width": "integer",
    "height": "integer",
    "frames": "integer",
    "cfg": "number",
    "fps": "number",
    "image": "string",
    "last_image": "string",
}


class MigrationError(RuntimeError):
    """A safe, actionable migration failure."""


@dataclass(frozen=True, slots=True)
class ImportPlan:
    source: Path
    mapping_source: Path | None
    legacy_name: str
    package_name: str
    registry_root: Path
    target: Path
    mapping: dict[str, Any]
    operations: tuple[str, ...]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Import legacy workflow JSON files as unsigned v1 custom packages."
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path.home() / ".config" / "vgen" / "workflows",
        help="legacy directory containing <name>.json and optional <name>.map.json",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        default=WorkflowRegistry().root,
        help="v1 workflow registry root",
    )
    parser.add_argument("--namespace", default="local", help="safe package namespace")
    parser.add_argument("--version", default="1.0.0", help="SemVer assigned to imported packages")
    parser.add_argument(
        "--workflow",
        action="append",
        default=[],
        help="import only this legacy workflow name; may be repeated",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write packages; without this flag the command is a read-only dry-run",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    return parser


def _safe_existing_file(root: Path, path: Path, label: str) -> Path:
    if path.is_symlink():
        raise MigrationError(f"{label} must not be a symbolic link: {path.name}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise MigrationError(f"cannot read {label}: {path.name}") from exc
    if not resolved.is_relative_to(root):
        raise MigrationError(f"{label} escapes the source directory: {path.name}")
    if not resolved.is_file():
        raise MigrationError(f"{label} is not a regular file: {path.name}")
    return resolved


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MigrationError(f"{label} is not valid UTF-8 JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise MigrationError(f"{label} must contain a JSON object: {path.name}")
    return value


def _load_graph(path: Path) -> dict[str, Any]:
    graph = _load_object(path, "workflow")
    if not graph or "nodes" in graph:
        raise MigrationError(f"workflow must be a non-empty ComfyUI API-format graph: {path.name}")
    return graph


def _mapping_rule_resolves(graph: dict[str, Any], rule: dict[str, Any]) -> bool:
    if rule.get("node") is not None:
        nodes = [graph.get(str(rule["node"]))]
    else:
        nodes = [
            node
            for node in graph.values()
            if isinstance(node, dict)
            and (node.get("_meta") or {}).get("title") == rule.get("title")
        ]
    if len(nodes) != 1 or not isinstance(nodes[0], dict):
        return False
    candidates = rule.get("input")
    candidates = [candidates] if isinstance(candidates, str) else candidates
    return isinstance(candidates, list) and any(
        isinstance(candidate, str) and candidate in (nodes[0].get("inputs") or {})
        for candidate in candidates
    )


def _load_mapping(path: Path | None, graph: dict[str, Any]) -> dict[str, Any]:
    if path is None:
        # Legacy DEFAULT_MAP intentionally listed more parameters than every
        # graph implemented. Materialize only rules which resolve in this graph
        # so the package does not advertise inputs it cannot accept.
        return {
            name: json.loads(json.dumps(rule))
            for name, rule in LEGACY_DEFAULT_MAPPING.items()
            if _mapping_rule_resolves(graph, rule)
        }
    mapping = _load_object(path, "mapping")
    for name, rule in mapping.items():
        if not isinstance(name, str) or not name or not isinstance(rule, dict):
            raise MigrationError(f"mapping entries must be named JSON objects: {path.name}")
        if not (rule.get("node") is not None or isinstance(rule.get("title"), str)):
            raise MigrationError(f"mapping entry {name!r} has no node or title: {path.name}")
        inputs = rule.get("input")
        if not isinstance(inputs, (str, list)) or not inputs:
            raise MigrationError(f"mapping entry {name!r} has no input: {path.name}")
    return mapping


def _package_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", value.casefold()).strip("._-")
    if not slug or not SAFE_SEGMENT.fullmatch(slug):
        raise MigrationError(f"legacy workflow name cannot form a safe package name: {value!r}")
    return slug


def _declared_operations(mapping: dict[str, Any]) -> tuple[str, ...]:
    image = mapping.get("image")
    last_image = mapping.get("last_image")
    image_optional = isinstance(image, dict) and isinstance(image.get("optional_connection"), dict)
    last_optional = isinstance(last_image, dict) and isinstance(
        last_image.get("optional_connection"), dict
    )
    if last_image is not None:
        if image is None:
            raise MigrationError("last_image mapping requires an image mapping")
        if image_optional and last_optional:
            return ("t2v", "i2v", "flf")
        return ("flf",)
    if image is not None:
        return ("t2v", "i2v") if image_optional else ("i2v",)
    return ("t2v",)


def _validate_operation_graphs(
    graph: dict[str, Any], mapping: dict[str, Any], operations: tuple[str, ...], name: str
) -> None:
    for operation in operations:
        parameters: dict[str, Any] = {}
        if operation in {"i2v", "flf"}:
            parameters["image"] = "vgen-migration-first-frame.png"
        elif "image" in mapping:
            parameters["image"] = None
        if operation == "flf":
            parameters["last_image"] = "vgen-migration-last-frame.png"
        elif "last_image" in mapping:
            parameters["last_image"] = None
        try:
            _, _, built_operation = build_comfy_graph(graph, mapping, parameters)
        except WorkflowBuildError as exc:
            raise MigrationError(
                f"workflow {name!r} cannot build declared {operation} graph: {exc}"
            ) from exc
        if built_operation != operation:
            raise MigrationError(
                f"workflow {name!r} built {built_operation} while validating {operation}"
            )


def discover_plans(
    source_dir: Path,
    destination: Path,
    namespace: str,
    version: str,
    selected: set[str],
) -> list[ImportPlan]:
    if not SAFE_SEGMENT.fullmatch(namespace):
        raise MigrationError("namespace must start with lowercase alphanumeric characters")
    if namespace == "market":
        raise MigrationError("namespace 'market' is reserved; migration provenance is custom")
    source_root = source_dir.expanduser().resolve(strict=True)
    if not source_root.is_dir():
        raise MigrationError(f"source is not a directory: {source_root}")
    destination_root = destination.expanduser().resolve()

    candidates = sorted(
        path
        for path in source_root.glob("*.json")
        if not path.name.endswith(".map.json") and (not selected or path.stem in selected)
    )
    found = {path.stem for path in candidates}
    missing = sorted(selected - found)
    if missing:
        raise MigrationError(f"selected workflows were not found: {missing}")
    if not candidates:
        raise MigrationError("no legacy workflow JSON files were found")

    plans: list[ImportPlan] = []
    names: dict[str, str] = {}
    for candidate in candidates:
        workflow_path = _safe_existing_file(source_root, candidate, "workflow")
        graph = _load_graph(workflow_path)
        raw_map = source_root / f"{candidate.stem}.map.json"
        mapping_path = (
            _safe_existing_file(source_root, raw_map, "mapping")
            if raw_map.exists() or raw_map.is_symlink()
            else None
        )
        mapping = _load_mapping(mapping_path, graph)
        package_name = _package_slug(candidate.stem)
        if package_name in names:
            raise MigrationError(
                f"workflow names {names[package_name]!r} and {candidate.stem!r} collide as "
                f"package {package_name!r}"
            )
        names[package_name] = candidate.stem
        # Provenance is an explicit storage boundary. This migration can only
        # create local custom packages and can never write into market/.
        target = (destination_root / "custom" / namespace / package_name / version).resolve()
        if not target.is_relative_to(destination_root):
            raise MigrationError("calculated destination escapes the registry root")
        if target.exists() or target.is_symlink():
            raise MigrationError(f"destination already exists: {target}")
        operations = _declared_operations(mapping)
        _validate_operation_graphs(graph, mapping, operations, candidate.stem)
        plans.append(
            ImportPlan(
                source=workflow_path,
                mapping_source=mapping_path,
                legacy_name=candidate.stem,
                package_name=package_name,
                registry_root=destination_root,
                target=target,
                mapping=mapping,
                operations=operations,
            )
        )
    return plans


def _parameter_schema(mapping: dict[str, Any]) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for name in sorted(mapping):
        property_schema: dict[str, Any] = {}
        if parameter_type := PARAMETER_TYPES.get(name):
            property_schema["type"] = parameter_type
        if name in {"image", "last_image"}:
            property_schema["contentMediaType"] = "image/*"
        properties[name] = property_schema
    return {"type": "object", "additionalProperties": False, "properties": properties}


def _manifest(plan: ImportPlan, namespace: str, version: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "id": f"{namespace}/{plan.package_name}",
        "version": version,
        "title": plan.legacy_name,
        "summary": "Locally imported legacy ComfyUI workflow; review before scheduling.",
        "license": "NOASSERTION",
        "provenance": "custom",
        "publisher": {"id": "local-import", "public_key": None},
        "source": "legacy-vgen-local-workflow",
        "parameters": _parameter_schema(plan.mapping),
        "variants": [
            {
                "name": "comfyui",
                "executor_type": "comfyui",
                "payload_format": "comfyui-api-graph/v1",
                "payload": "workflow.json",
                "mapping": "mapping.json",
                "operations": list(plan.operations),
                "models": [],
            }
        ],
    }


def _build_package(plan: ImportPlan, package_dir: Path, namespace: str, version: str) -> str:
    package_dir.mkdir()
    shutil.copyfile(plan.source, package_dir / "workflow.json")
    (package_dir / "mapping.json").write_text(
        json.dumps(plan.mapping, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest = _manifest(plan, namespace, version)
    (package_dir / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    (package_dir / "README.md").write_text(
        "\n".join(
            [
                f"# {plan.legacy_name}",
                "",
                "Imported locally from the legacy VGen workflow directory.",
                "",
                "Before scheduling this package, review:",
                "",
                "- model and custom-node dependencies;",
                "- model source, digest, size and license;",
                "- parameter mappings and optional image connections;",
                "- all 0/1/2-image operations declared in the manifest.",
                "",
                "This unsigned custom package is never a market release.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    write_checksums(package_dir)
    parsed, digest, signed = validate_package(package_dir, allow_unsigned=True)
    if signed or parsed.provenance != "custom":
        raise MigrationError("migrated workflow did not validate as unsigned custom provenance")
    return digest


def execute_plan(plan: ImportPlan, namespace: str, version: str, *, apply: bool) -> dict[str, Any]:
    if apply:
        plan.target.parent.mkdir(parents=True, exist_ok=True)
        if not plan.target.parent.resolve().is_relative_to(plan.registry_root):
            raise MigrationError("destination parent escapes the registry root")
        with tempfile.TemporaryDirectory(
            prefix=f".{plan.package_name}-", dir=plan.target.parent
        ) as temporary:
            package_dir = Path(temporary) / "package"
            digest = _build_package(plan, package_dir, namespace, version)
            package_dir.rename(plan.target)
    else:
        with tempfile.TemporaryDirectory(prefix="vgen-workflow-dry-run-") as temporary:
            package_dir = Path(temporary) / "package"
            digest = _build_package(plan, package_dir, namespace, version)
            if digest != package_digest(package_dir):
                raise MigrationError("workflow digest changed during dry-run validation")
    return {
        "legacy_name": plan.legacy_name,
        "id": f"{namespace}/{plan.package_name}",
        "version": version,
        "operations": list(plan.operations),
        "used_mapping_file": plan.mapping_source is not None,
        "digest": f"sha256:{digest}",
        "target": str(plan.target),
        "written": apply,
    }


def run(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        # Validate SemVer and the composed identifier through the canonical model
        # before creating any destination directory.
        WorkflowManifest.model_validate(
            {
                "schema_version": 1,
                "id": f"{arguments.namespace}/placeholder",
                "version": arguments.version,
                "title": "placeholder",
                "summary": "validation placeholder",
                "license": "NOASSERTION",
                "provenance": "custom",
                "publisher": {"id": "local-import"},
                "variants": [
                    {
                        "name": "comfyui",
                        "executor_type": "comfyui",
                        "payload_format": "comfyui-api-graph/v1",
                        "payload": "workflow.json",
                        "operations": ["t2v"],
                    }
                ],
            }
        )
        plans = discover_plans(
            arguments.source_dir,
            arguments.destination,
            arguments.namespace,
            arguments.version,
            set(arguments.workflow),
        )
        results = [
            execute_plan(
                plan,
                arguments.namespace,
                arguments.version,
                apply=arguments.apply,
            )
            for plan in plans
        ]
    except (MigrationError, OSError, ValueError) as exc:
        if arguments.json:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"migration failed: {exc}", file=sys.stderr)
        return 2

    payload = {
        "ok": True,
        "mode": "apply" if arguments.apply else "dry-run",
        "count": len(results),
        "workflows": results,
        "task_history_imported": False,
    }
    if arguments.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"{payload['mode']}: validated {len(results)} workflow(s)")
        for result in results:
            action = "wrote" if result["written"] else "would write"
            print(
                f"- {result['id']}@{result['version']} {result['digest']} "
                f"operations={','.join(result['operations'])} {action} {result['target']}"
            )
        print("task history imported: no")
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
