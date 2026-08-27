"""Shared bounded public media facts for the v1 wire contract."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final

MEDIA_PROBE_LIMITS: Final[Mapping[str, tuple[int, int]]] = MappingProxyType(
    {
        "width": (1, 131_072),
        "height": (1, 131_072),
        "frames": (0, 10_000_000),
        "duration_ms": (0, 604_800_000),
        "denoise_steps": (0, 100_000),
        "output_count": (1, 8),
    }
)


def canonical_media_probes(value: Mapping[str, Any]) -> dict[str, int | None]:
    """Drop executor-native values that are not exact v1 integer probes."""

    result: dict[str, int | None] = {}
    for name, (minimum, maximum) in MEDIA_PROBE_LIMITS.items():
        if name not in value:
            continue
        item = value[name]
        if item is None:
            result[name] = None
        elif type(item) is int and minimum <= item <= maximum:
            result[name] = item
    return result
