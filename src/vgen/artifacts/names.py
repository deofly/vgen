"""Privacy-safe public filenames for typed artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final

# Keep this deliberately small and deterministic.  ``mimetypes.guess_extension``
# is platform-dependent and accepts types installed by the host OS.  Artifact
# metadata crosses the E2EE control plane, so only reviewed public media types
# may influence a public filename.
MEDIA_TYPE_EXTENSIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "audio/aac": ".aac",
        "audio/flac": ".flac",
        "audio/mpeg": ".mp3",
        "audio/ogg": ".ogg",
        "audio/wav": ".wav",
        "image/gif": ".gif",
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "video/mp4": ".mp4",
        "video/quicktime": ".mov",
        "video/webm": ".webm",
        "video/x-matroska": ".mkv",
    }
)


def with_safe_media_extension(filename: str, media_type: str | None) -> str:
    """Add a reviewed extension to an extensionless or generic ``.bin`` basename.

    The caller remains responsible for supplying a privacy-safe basename.  This
    helper never derives a name from an executor's private local output path and
    never replaces a specific existing extension.
    """

    if not filename or Path(filename).name != filename:
        raise ValueError("artifact filename must be a basename")
    suffix = Path(filename).suffix
    if suffix and suffix.casefold() != ".bin":
        return filename
    extension = MEDIA_TYPE_EXTENSIONS.get(media_type.casefold()) if media_type else None
    if extension is None:
        return filename
    stem = filename[: -len(suffix)] if suffix else filename.rstrip(".")
    return f"{stem or 'output'}{extension}"
