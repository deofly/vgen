"""Public SDK exception types."""

from __future__ import annotations


class VGenSdkError(Exception):
    """Base class for SDK failures."""


class CredentialError(VGenSdkError, ValueError):
    """A credential is invalid or cannot be stored safely."""


class DecryptionError(VGenSdkError, ValueError):
    """Ciphertext could not be authenticated or decrypted."""


class SignatureError(VGenSdkError, ValueError):
    """An HTTP message signature is malformed or invalid."""
