"""Gateway administration and process entry point without import-time I/O."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
from collections.abc import Sequence
from pathlib import Path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vgen-gateway", description="VGen Gateway v1")
    parser.add_argument("--database", "--db", dest="database", default="./data/vgen-gateway.db")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="initialize an empty Gateway database")
    initialize.add_argument("--bootstrap-code-file")
    commands.add_parser("doctor", help="check database schema and WAL configuration")
    backup = commands.add_parser("backup", help="create an online SQLite backup")
    backup.add_argument("output")
    backup.add_argument("--overwrite", action="store_true")
    serve = commands.add_parser("serve", help="run the Gateway HTTP service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8787, type=int)
    serve.add_argument("--artifact-root")
    serve.add_argument("--release-root")
    serve.add_argument("--release-public-base-url")
    serve.add_argument(
        "--serve-release-files",
        action="store_true",
        default=None,
        help="serve declared public installers from the Gateway (development only)",
    )
    serve.add_argument("--bootstrap-code-file")
    serve.add_argument("--no-docs", action="store_true")
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    from .database import GatewayDatabase

    if arguments.command == "init":
        database = GatewayDatabase(arguments.database)
        database.close()
        destination = (
            Path(arguments.bootstrap_code_file).expanduser()
            if arguments.bootstrap_code_file
            else Path(arguments.database).expanduser().with_name("bootstrap-code")
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, (secrets.token_urlsafe(32) + "\n").encode())
        finally:
            os.close(descriptor)
        return 0

    if arguments.command == "doctor":
        database = GatewayDatabase(arguments.database)
        try:
            report = database.health()
        finally:
            database.close()
        print(json.dumps(report, sort_keys=True))
        return 0 if report["ok"] and report["journal_mode"] == "wal" else 1

    if arguments.command == "backup":
        database = GatewayDatabase(arguments.database)
        try:
            database.backup(
                Path(arguments.output).expanduser(),
                overwrite=arguments.overwrite,
            )
        finally:
            database.close()
        return 0

    bootstrap_code = os.getenv("VGEN_GATEWAY_BOOTSTRAP_CODE")
    if arguments.bootstrap_code_file:
        code_path = Path(arguments.bootstrap_code_file).expanduser()
        if os.name != "nt" and stat.S_IMODE(code_path.stat().st_mode) & 0o077:
            raise SystemExit("bootstrap code file must have mode 0600")
        bootstrap_code = code_path.read_text().strip()
    if not bootstrap_code:
        default_code_path = Path(arguments.database).expanduser().with_name("bootstrap-code")
        if default_code_path.is_file():
            if os.name != "nt" and stat.S_IMODE(default_code_path.stat().st_mode) & 0o077:
                raise SystemExit("bootstrap code file must have mode 0600")
            bootstrap_code = default_code_path.read_text().strip()
    if not bootstrap_code:
        database = GatewayDatabase(arguments.database)
        try:
            bootstrapped = database.fetchone(
                "SELECT id FROM users WHERE is_operator=1 AND status='active' LIMIT 1"
            )
        finally:
            database.close()
        if bootstrapped is None:
            default_code_path.parent.mkdir(parents=True, exist_ok=True)
            bootstrap_code = secrets.token_urlsafe(32)
            try:
                descriptor = os.open(
                    default_code_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                bootstrap_code = default_code_path.read_text().strip()
            else:
                try:
                    os.write(descriptor, (bootstrap_code + "\n").encode())
                finally:
                    os.close(descriptor)
        else:
            # Bootstrap has already been consumed. Keep the route
            # cryptographically unreachable without retaining another
            # operational secret on disk.
            bootstrap_code = secrets.token_urlsafe(32)
    import uvicorn

    from .app import create_app

    application = create_app(
        database_path=arguments.database,
        artifact_root=arguments.artifact_root,
        release_root=arguments.release_root,
        release_public_base_url=arguments.release_public_base_url,
        serve_release_files=arguments.serve_release_files,
        bootstrap_code=bootstrap_code,
        docs_enabled=(
            not arguments.no_docs
            and os.getenv("VGEN_GATEWAY_DOCS", "1").strip().lower()
            not in {"0", "false", "no", "off"}
        ),
    )
    # Artifact capability tokens are intentionally opaque but may be carried
    # in request paths by provider adapters. Uvicorn's stock access
    # logger prints the full path, so it is disabled instead of risking a
    # signed ticket in logs. Structured audit events remain available in the
    # Gateway database.
    uvicorn.run(application, host=arguments.host, port=arguments.port, access_log=False)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
