"""Cross-platform canonical paths for signed workflow packages."""

from __future__ import annotations

import re
import unicodedata
from pathlib import PurePosixPath

_WINDOWS_RESERVED_STEMS = frozenset(
    {"aux", "clock$", "con", "conin$", "conout$", "nul", "prn"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
    # Windows treats the Unicode superscript digits below as DOS device
    # suffixes too (for example COM¹ and LPT²).
    | {f"com{index}" for index in "¹²³"}
    | {f"lpt{index}" for index in "¹²³"}
)
_WINDOWS_FORBIDDEN_CHARACTERS = frozenset('<>:"|?*')


def canonical_package_path(
    value: str,
    *,
    label: str,
    allow_backslash: bool = False,
) -> str:
    """Return one portable spelling or reject platform-specific aliases."""

    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if not allow_backslash and "\\" in value:
        raise ValueError(f"{label} must use forward slashes")
    normalized = value.replace("\\", "/")
    if normalized != unicodedata.normalize("NFC", normalized):
        raise ValueError(f"{label} must use Unicode NFC")
    parts = normalized.split("/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or not normalized.strip()
        or "\x00" in normalized
        or "://" in normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError(f"{label} must be a non-empty relative package path")
    for part in parts:
        # DOS device aliases are resolved after trailing spaces and dots in
        # the stem are ignored, including before an ordinary extension.
        windows_stem = part.partition(".")[0].rstrip(" .").casefold()
        if (
            part.endswith((" ", "."))
            or any(character in _WINDOWS_FORBIDDEN_CHARACTERS for character in part)
            or any(ord(character) < 32 for character in part)
            or windows_stem in _WINDOWS_RESERVED_STEMS
        ):
            raise ValueError(f"{label} is not portable across supported filesystems")
    return path.as_posix()


def package_path_key(value: str, *, label: str = "package path") -> str:
    """Return the collision key used by case-insensitive supported filesystems."""

    canonical = canonical_package_path(value, label=label)
    return "/".join(part.casefold() for part in PurePosixPath(canonical).parts)


__all__ = ["canonical_package_path", "package_path_key"]
