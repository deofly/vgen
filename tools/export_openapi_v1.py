#!/usr/bin/env python3
"""Export the deterministic VGen Gateway OpenAPI v1 contract.

The exporter creates an isolated, temporary Gateway database.  It never reads
deployment configuration or runtime secrets.  Use ``--check`` in CI after the
committed contract has been generated once.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from vgen.gateway.app import create_app
from vgen.gateway.artifacts import LocalArtifactStore

DEFAULT_OUTPUT = Path("schemas/openapi-v1.json")
SENSITIVE_NAMES = {
    "bootstrap_code",
    "invite_uri",
    "mnemonic",
    "private_key",
    "recovery_phrase",
    "secret",
    "session_token",
    "signed_url",
    "token",
}
EXAMPLE_KEYS = {"default", "example", "examples"}


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, (*path, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, (*path, str(index)))


def _assert_safe_contract(schema: dict[str, Any], bootstrap_marker: str) -> None:
    if not str(schema.get("openapi", "")).startswith("3.1."):
        raise RuntimeError("Gateway must export an OpenAPI 3.1 contract")

    paths = schema.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise RuntimeError("Gateway OpenAPI contract has no paths")
    invalid_paths = sorted(
        path for path in paths if path not in {"/healthz"} and not path.startswith("/api/v1/")
    )
    if invalid_paths:
        raise RuntimeError(f"OpenAPI contains non-v1 public paths: {invalid_paths}")

    encoded = json.dumps(schema, sort_keys=True)
    if bootstrap_marker in encoded:
        raise RuntimeError("OpenAPI unexpectedly contains the exporter bootstrap marker")

    for path, value in _walk(schema):
        lowered = {part.lower().replace("-", "_") for part in path}
        if lowered & SENSITIVE_NAMES and path and path[-1].lower() in EXAMPLE_KEYS:
            if value not in (None, "", [], {}):
                location = ".".join(path)
                raise RuntimeError(f"Sensitive OpenAPI example/default at {location}")


def build_contract() -> dict[str, Any]:
    bootstrap_marker = "vgen-openapi-exporter-non-runtime-marker"
    with tempfile.TemporaryDirectory(prefix="vgen-openapi-") as temporary:
        root = Path(temporary)
        test_store = LocalArtifactStore(root / "artifacts", b"openapi-test-key" * 2)
        app = create_app(
            database_path=str(root / "gateway.db"),
            bootstrap_code=bootstrap_marker,
            artifact_store_override=test_store,
            docs_enabled=True,
            require_request_signatures=True,
            sweep_interval_seconds=3600,
        )
        try:
            schema = app.openapi()
            _assert_safe_contract(schema, bootstrap_marker)
            return schema
        finally:
            app.state.db.close()


def canonical_bytes(schema: dict[str, Any]) -> bytes:
    return (json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the committed file differs; do not write it",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    expected = canonical_bytes(build_contract())
    destination = arguments.output
    if arguments.check:
        try:
            current = destination.read_bytes()
        except FileNotFoundError:
            print(f"OpenAPI contract is missing: {destination}", file=sys.stderr)
            return 1
        if current != expected:
            print(f"OpenAPI contract is stale: {destination}", file=sys.stderr)
            return 1
        print(f"OpenAPI contract is current: {destination}")
        return 0

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(expected)
    print(f"Wrote {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
