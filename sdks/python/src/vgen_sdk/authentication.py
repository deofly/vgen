"""Payload builders for VGen API Service challenge authentication."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .credentials import ServiceCredentials
from .encoding import b64url_encode
from .keys import DeviceKeys, sign_message


def build_service_challenge_request(
    credentials_or_service_id: ServiceCredentials | str,
) -> dict[str, str]:
    """Build the body for ``POST /api/v1/auth/challenges``."""

    service_id = (
        credentials_or_service_id.service_id
        if isinstance(credentials_or_service_id, ServiceCredentials)
        else credentials_or_service_id
    )
    if not isinstance(service_id, str) or not service_id:
        raise ValueError("service_id is required")
    return {"principal_type": "service", "service_id": service_id}


def sign_service_challenge(keys: DeviceKeys, challenge: str) -> str:
    """Sign the challenge string exactly as required by the current Gateway."""

    if not isinstance(challenge, str) or not challenge:
        raise ValueError("challenge is required")
    return b64url_encode(sign_message(keys.signing_private_key, challenge.encode("utf-8")))


def build_service_session_request(
    credentials: ServiceCredentials,
    challenge_response: Mapping[str, Any],
) -> dict[str, str]:
    """Build the body for ``POST /api/v1/auth/sessions``.

    ``challenge_response`` is the decoded JSON object returned by the Gateway.
    This function performs no network or local storage operations.
    """

    try:
        challenge_id = challenge_response["challenge_id"]
        challenge = challenge_response["challenge"]
    except (KeyError, TypeError) as exc:
        raise ValueError("Gateway challenge response is incomplete") from exc
    if (
        not isinstance(challenge_id, str)
        or not challenge_id
        or not isinstance(challenge, str)
        or not challenge
    ):
        raise ValueError("Gateway challenge response is incomplete")
    principal_type = challenge_response.get("principal_type")
    if principal_type is not None and principal_type != "service":
        raise ValueError("Gateway challenge is not for a Service principal")
    returned_service_id = challenge_response.get("service_id")
    if returned_service_id is not None and returned_service_id != credentials.service_id:
        raise ValueError("Gateway challenge is for a different Service")
    return {
        "principal_type": "service",
        "service_id": credentials.service_id,
        "challenge_id": challenge_id,
        "signature": sign_service_challenge(credentials.device_keys, challenge),
    }
