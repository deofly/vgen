"""Provider-neutral artifact transfer primitives.

The worker only consumes short-lived transfer tickets. Provider details remain
inside adapters; an OSS ticket may carry object-scoped STS credentials, never a
long-lived account AccessKey.
"""

from .base import (
    ArtifactAdapterRegistry,
    ArtifactDescriptor,
    ArtifactTicketIssuer,
    ArtifactTransferError,
    ArtifactTransport,
    ProgressCallback,
    TransferReceipt,
    TransferTicket,
)
from .http import HttpArtifactAdapter
from .local import LocalArtifactAdapter
from .names import MEDIA_TYPE_EXTENSIONS, with_safe_media_extension
from .oss import OssStsArtifactAdapter

__all__ = [
    "ArtifactAdapterRegistry",
    "ArtifactDescriptor",
    "ArtifactTicketIssuer",
    "ArtifactTransferError",
    "ArtifactTransport",
    "HttpArtifactAdapter",
    "LocalArtifactAdapter",
    "OssStsArtifactAdapter",
    "MEDIA_TYPE_EXTENSIONS",
    "ProgressCallback",
    "TransferReceipt",
    "TransferTicket",
    "with_safe_media_extension",
]
