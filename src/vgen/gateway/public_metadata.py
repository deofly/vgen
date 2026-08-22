"""Strict, plaintext-safe metadata accepted by the Gateway control plane.

The Gateway is an E2EE metadata service, not a generic JSON document store.
Keeping these validators independent from Pydantic lets both the HTTP boundary
and repository-internal callers enforce the same closed contract.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_PUBLIC_REQUIREMENT_KEYS = frozenset(
    {
        "operation",
        "payload_format",
        "executor_min_version",
        "runtime_min_version",
        "min_vram_bytes",
        "min_ram_bytes",
        "model_digests",
        "output_count",
    }
)
_MEDIA_METADATA_KEYS = frozenset(
    {
        "filename",
        "media_type",
        "width",
        "height",
        "frames",
        "duration_ms",
        "denoise_steps",
        "output_count",
    }
)
_OPERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_PAYLOAD_FORMAT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,119}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{64}$")
_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_MEDIA_TYPE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}$"
)


@dataclass(frozen=True, slots=True)
class PublicMetadataError(ValueError):
    field: str
    reason: str

    def __str__(self) -> str:
        return f"{self.field}: {self.reason}"


def _mapping(value: object, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PublicMetadataError(field, "object_required")
    return value


def _closed_keys(value: Mapping[str, Any], allowed: frozenset[str], *, field: str) -> None:
    if any(not isinstance(key, str) or key not in allowed for key in value):
        # Do not reflect an attacker-controlled key. It could itself contain
        # prompt text or another secret.
        raise PublicMetadataError(field, "unsupported_field")


def _bounded_int(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PublicMetadataError(field, "integer_required")
    if value < minimum or value > maximum:
        raise PublicMetadataError(field, "integer_out_of_range")
    return value


def validate_public_requirements(value: object) -> dict[str, Any]:
    """Return the canonical closed set of non-sensitive scheduling facts."""

    raw = _mapping(value, field="public_requirements")
    _closed_keys(raw, _PUBLIC_REQUIREMENT_KEYS, field="public_requirements")
    if len(raw) > len(_PUBLIC_REQUIREMENT_KEYS):
        raise PublicMetadataError("public_requirements", "too_many_fields")

    result: dict[str, Any] = {}
    for name, pattern in (
        ("operation", _OPERATION),
        ("payload_format", _PAYLOAD_FORMAT),
        ("executor_min_version", _VERSION),
        ("runtime_min_version", _VERSION),
    ):
        if name not in raw:
            continue
        item = raw[name]
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise PublicMetadataError("public_requirements", f"invalid_{name}")
        result[name] = item

    for name, maximum in (
        ("min_vram_bytes", 1 << 60),
        ("min_ram_bytes", 1 << 60),
    ):
        if name in raw:
            result[name] = _bounded_int(
                raw[name], field="public_requirements", minimum=0, maximum=maximum
            )
    if "output_count" in raw:
        result["output_count"] = _bounded_int(
            raw["output_count"], field="public_requirements", minimum=1, maximum=8
        )

    if "model_digests" in raw:
        digests = raw["model_digests"]
        if not isinstance(digests, list) or len(digests) > 128:
            raise PublicMetadataError("public_requirements", "invalid_model_digests")
        canonical: list[str] = []
        seen: set[str] = set()
        for digest in digests:
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise PublicMetadataError("public_requirements", "invalid_model_digests")
            normalized = digest.lower()
            if not normalized.startswith("sha256:"):
                normalized = "sha256:" + normalized
            if normalized in seen:
                raise PublicMetadataError("public_requirements", "duplicate_model_digest")
            seen.add(normalized)
            canonical.append(normalized)
        result["model_digests"] = canonical
    return result


def validate_artifact_media_metadata(value: object) -> dict[str, Any]:
    """Return bounded media facts; reject free-form Worker/client prose."""

    raw = _mapping(value, field="media_metadata")
    _closed_keys(raw, _MEDIA_METADATA_KEYS, field="media_metadata")
    if len(raw) > len(_MEDIA_METADATA_KEYS):
        raise PublicMetadataError("media_metadata", "too_many_fields")

    result: dict[str, Any] = {}
    if "filename" in raw:
        filename = raw["filename"]
        if not isinstance(filename, str) or not _FILENAME.fullmatch(filename):
            raise PublicMetadataError("media_metadata", "invalid_filename")
        result["filename"] = filename
    if "media_type" in raw:
        media_type = raw["media_type"]
        if not isinstance(media_type, str) or not _MEDIA_TYPE.fullmatch(media_type):
            raise PublicMetadataError("media_metadata", "invalid_media_type")
        result["media_type"] = media_type.lower()

    for name, minimum, maximum in (
        ("width", 1, 131_072),
        ("height", 1, 131_072),
        ("frames", 0, 10_000_000),
        ("duration_ms", 0, 604_800_000),
        ("denoise_steps", 0, 100_000),
        ("output_count", 1, 8),
    ):
        if name not in raw:
            continue
        if raw[name] is None:
            result[name] = None
            continue
        result[name] = _bounded_int(
            raw[name], field="media_metadata", minimum=minimum, maximum=maximum
        )
    return result
