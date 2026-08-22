"""VGen shared runtime package."""

from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _product_version() -> str:
    """Resolve the checkout version, then fall back to installed metadata."""

    project_file = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if project_file.is_file():
        try:
            with project_file.open("rb") as handle:
                value = tomllib.load(handle)["project"]["version"]
        except (OSError, KeyError, tomllib.TOMLDecodeError):
            pass
        else:
            if isinstance(value, str) and value:
                return value
    try:
        return version("vgen")
    except PackageNotFoundError:
        return "unknown"


__version__ = _product_version()

__all__ = ["__version__", "crypto", "protocol"]
