#!/usr/bin/env python3
"""Fail when a public source tree contains local state or likely live secrets."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_TRACKED_FILE_BYTES = 10 * 1024 * 1024
FORBIDDEN_NAMES = {
    ".DS_Store",
    ".coverage",
    ".env",
    ".aicoding-chat-workspace",
    ":memory:",
    "credentials.json",
    "worker-credentials.json",
}
FORBIDDEN_SUFFIXES = {".db", ".key", ".log", ".pem", ".seed", ".sqlite", ".sqlite3"}
CONTENT_RULES = (
    ("private key material", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("AWS access key ID", re.compile(rb"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])")),
    ("Alibaba Cloud access key ID", re.compile(rb"(?<![A-Za-z0-9])LTAI[A-Za-z0-9]{12,24}(?![A-Za-z0-9])")),
)


def tracked_files() -> list[Path]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required for the public repository check")
    completed = subprocess.run(
        [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        path
        for value in completed.stdout.split(b"\0")
        if value and (path := ROOT / value.decode()).exists()
    ]


def violations() -> list[str]:
    failures: list[str] = []
    scanner = Path(__file__).resolve()
    for path in tracked_files():
        relative = path.relative_to(ROOT)
        populated_environment = path.name.startswith(".env.") and path.name != ".env.example"
        if (
            path.name in FORBIDDEN_NAMES
            or populated_environment
            or path.suffix.lower() in FORBIDDEN_SUFFIXES
        ):
            failures.append(f"forbidden tracked file: {relative}")
            continue
        try:
            size = path.stat().st_size
            content = path.read_bytes()
        except OSError as exc:
            failures.append(f"cannot inspect tracked file {relative}: {type(exc).__name__}")
            continue
        if size > MAX_TRACKED_FILE_BYTES:
            failures.append(f"tracked file exceeds 10 MiB: {relative}")
        if path.resolve() == scanner:
            continue
        for label, pattern in CONTENT_RULES:
            if pattern.search(content):
                failures.append(f"{label} found in: {relative}")
    return failures


def main() -> None:
    failures = violations()
    if failures:
        raise SystemExit("Public repository check failed:\n- " + "\n- ".join(failures))
    print("Public repository check passed: tracked files contain no local state or known key forms")


if __name__ == "__main__":
    main()
