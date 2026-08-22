"""Canonical encodings used by signed VGen objects."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise TypeError("base64url value must be a string")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64url value") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(f"decoded value must contain {expected_length} bytes")
    return decoded


def canonical_json(value: Mapping[str, Any] | list[Any]) -> bytes:
    """Serialize a signed object deterministically, without insignificant space."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
