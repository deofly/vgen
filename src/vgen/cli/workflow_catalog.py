"""Human-facing workflow codes, separate from immutable package identities."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from vgen.market.models import validate_workflow_id, validate_workflow_version
from vgen.market.registry import MAX_INDEX_BYTES, RegistryError

DEFAULT_WORKFLOW_INDEX = "https://vgen.zcbiz.com/marketplace/index.json"
WORKFLOW_CODE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def workflow_index() -> str:
    return os.environ.get("VGEN_WORKFLOW_MARKET_INDEX", DEFAULT_WORKFLOW_INDEX)


def entry_code(entry: dict[str, Any]) -> str:
    workflow_id = entry.get("id")
    try:
        validate_workflow_id(workflow_id)
    except (ValueError, TypeError) as exc:
        raise RegistryError("market workflow id is invalid") from exc
    code = entry.get("code", workflow_id.split("/", 1)[1])
    if not isinstance(code, str) or not WORKFLOW_CODE.fullmatch(code):
        raise RegistryError("market workflow code must be a lowercase portable identifier")
    return code


def code_candidates(code: str, workflow_ids: set[str], entries: list[dict[str, Any]]) -> set[str]:
    ids = workflow_ids | {entry["id"] for entry in entries}
    return {workflow_id for workflow_id in ids if workflow_id.split("/", 1)[1] == code} | {
        entry["id"] for entry in entries if entry_code(entry) == code
    }


def resolve_code(code: str, workflow_ids: set[str], entries: list[dict[str, Any]]) -> str | None:
    candidates = code_candidates(code, workflow_ids, entries)
    if len(candidates) > 1:
        raise RegistryError(
            f"workflow code {code!r} is ambiguous; use one of: {', '.join(sorted(candidates))}"
        )
    return next(iter(candidates), None)


def display_code(workflow_id: str, workflow_ids: set[str], entries: list[dict[str, Any]]) -> str:
    codes = sorted({entry_code(entry) for entry in entries if entry["id"] == workflow_id})
    codes.append(workflow_id.split("/", 1)[1])
    for code in codes:
        if code_candidates(code, workflow_ids, entries) == {workflow_id}:
            return code
    return workflow_id


def _cache_path(root: Path | None, index: str) -> Path | None:
    if root is None:
        return None
    return root / "catalog-cache" / (hashlib.sha256(index.encode()).hexdigest() + ".json")


def read_catalog_cache(root: Path | None, index: str) -> list[dict[str, Any]]:
    path = _cache_path(root, index)
    if path is None:
        return []
    try:
        if path.is_symlink() or path.stat().st_size > MAX_INDEX_BYTES:
            return []
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            return []
        entries = value.get("workflows")
        if not isinstance(entries, list) or not all(isinstance(row, dict) for row in entries):
            return []
        for entry in entries:
            entry_code(entry)
            if not isinstance(entry.get("version"), str):
                return []
            validate_workflow_version(entry["version"])
        return entries
    except (OSError, ValueError, RegistryError):
        return []


def write_catalog_cache(root: Path | None, index: str, entries: list[dict[str, Any]]) -> None:
    path = _cache_path(root, index)
    if path is None:
        return
    # An index refresh must not silently reassign a previously learned code.
    previous = read_catalog_cache(root, index)
    previous_ids = {row["id"] for row in previous}
    incoming_ids = {row["id"] for row in entries}
    for entry in entries:
        code = entry_code(entry)
        old = code_candidates(code, previous_ids, previous)
        new = code_candidates(code, incoming_ids, entries)
        if old and old != new:
            raise RegistryError(f"market workflow code {code!r} changed identity; use the full id")
    data = (
        json.dumps({"schema_version": 1, "workflows": entries}, ensure_ascii=False) + "\n"
    ).encode()
    if len(data) > MAX_INDEX_BYTES:
        raise RegistryError("workflow catalog cache exceeds its size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".catalog-", delete=False
        ) as handle:
            temporary = handle.name
            handle.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
