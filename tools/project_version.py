#!/usr/bin/env python3
"""Read VGen's product version from its single hand-maintained source."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_RELEASE_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def project_version(repository: Path | None = None) -> str:
    """Return the validated ``project.version`` from ``pyproject.toml``."""

    root = (repository or _REPOSITORY_ROOT).resolve()
    project_file = root / "pyproject.toml"
    try:
        with project_file.open("rb") as handle:
            value = tomllib.load(handle)["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError(f"cannot read VGen version from {project_file}") from exc
    if not isinstance(value, str) or _RELEASE_VERSION.fullmatch(value) is None:
        raise RuntimeError(
            "VGen project.version must be an unprefixed MAJOR.MINOR.PATCH release version"
        )
    return value


def main() -> int:
    print(project_version())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
