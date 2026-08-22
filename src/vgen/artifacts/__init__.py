"""Provider-neutral artifact transfer primitives.

The worker only consumes short-lived transfer tickets.  Storage provider
credentials and provider-specific concepts (buckets, regions, STS, and so on)
belong behind the ticket issuer on the Gateway.
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

__all__ = [
    "ArtifactAdapterRegistry",
    "ArtifactDescriptor",
    "ArtifactTicketIssuer",
    "ArtifactTransferError",
    "ArtifactTransport",
    "HttpArtifactAdapter",
    "LocalArtifactAdapter",
    "MEDIA_TYPE_EXTENSIONS",
    "ProgressCallback",
    "TransferReceipt",
    "TransferTicket",
    "with_safe_media_extension",
]
