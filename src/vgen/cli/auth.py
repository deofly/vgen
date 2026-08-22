from __future__ import annotations

from vgen.crypto import DeviceKeys, b64url_encode, sign_message

from .client import GatewayClient
from .identity_store import DeviceIdentity
from .profile import GatewayProfile, ProfileStore
from .session_store import SessionStore, StoredSession


def authenticate_device_session(
    profile: GatewayProfile, identity: DeviceIdentity
) -> StoredSession:
    """Authenticate a Device without mutating any local Profile or session state."""

    anonymous = GatewayClient(profile)
    try:
        challenge = anonymous.request(
            "POST",
            "/api/v1/auth/challenges",
            json_body={
                "principal_type": "device",
                "device_id": profile.device_id or identity.device_id,
            },
            auth=False,
        )
        signature = sign_message(
            identity.device_keys.signing_private_key,
            str(challenge["challenge"]).encode("utf-8"),
        )
        response = anonymous.request(
            "POST",
            "/api/v1/auth/sessions",
            json_body={
                "principal_type": "device",
                "device_id": profile.device_id or identity.device_id,
                "challenge_id": challenge["challenge_id"],
                "signature": b64url_encode(signature),
                "device_certificate": identity.certificate.to_dict(),
                "root_key_id": identity.root_key_id,
                "root_signing_public_key": identity.root_signing_public_key,
                "root_encryption_public_key": identity.root_encryption_public_key,
            },
            auth=False,
        )
    finally:
        anonymous.close()
    session = StoredSession(
        token=str(response.get("session_token") or response.get("token")),
        expires_at=float(response["expires_at"]),
        user_id=response.get("user_id"),
        device_id=response.get("device_id") or profile.device_id or identity.device_id,
    )
    return session


def login_session(profile: GatewayProfile, identity: DeviceIdentity) -> StoredSession:
    """Exchange a signed, one-use challenge for a stored 15-minute session."""

    session = authenticate_device_session(profile, identity)
    SessionStore().save(profile.name, session)
    ProfileStore().update_binding(
        profile.name,
        user_id=session.user_id or profile.user_id,
        device_id=session.device_id or profile.device_id,
    )
    return session


def login_worker_session(
    profile: GatewayProfile,
    worker_id: str,
    keys: DeviceKeys,
) -> dict[str, object]:
    """Prove possession of a Worker key and obtain a short session in memory."""

    anonymous = GatewayClient(profile)
    try:
        challenge = anonymous.request(
            "POST",
            "/api/v1/auth/challenges",
            json_body={"principal_type": "worker", "worker_id": worker_id},
            auth=False,
        )
        signature = sign_message(
            keys.signing_private_key,
            str(challenge["challenge"]).encode("utf-8"),
        )
        response = anonymous.request(
            "POST",
            "/api/v1/auth/sessions",
            json_body={
                "principal_type": "worker",
                "worker_id": worker_id,
                "challenge_id": challenge["challenge_id"],
                "signature": b64url_encode(signature),
            },
            auth=False,
        )
    finally:
        anonymous.close()
    token = response.get("session_token") or response.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("Gateway returned no Worker session token")
    return {
        "token": token,
        "expires_at": float(response["expires_at"]),
        "worker_id": response.get("worker_id") or worker_id,
    }


def login_service_session(
    profile: GatewayProfile,
    service_id: str,
    keys: DeviceKeys,
) -> dict[str, object]:
    """Authenticate a scoped API Service using its own signing key."""

    anonymous = GatewayClient(profile)
    try:
        challenge = anonymous.request(
            "POST",
            "/api/v1/auth/challenges",
            json_body={"principal_type": "service", "service_id": service_id},
            auth=False,
        )
        signature = sign_message(
            keys.signing_private_key,
            str(challenge["challenge"]).encode("utf-8"),
        )
        response = anonymous.request(
            "POST",
            "/api/v1/auth/sessions",
            json_body={
                "principal_type": "service",
                "service_id": service_id,
                "challenge_id": challenge["challenge_id"],
                "signature": b64url_encode(signature),
            },
            auth=False,
        )
    finally:
        anonymous.close()
    token = response.get("session_token") or response.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("Gateway returned no Service session token")
    return {
        "token": token,
        "expires_at": float(response["expires_at"]),
        "service_id": response.get("service_id") or service_id,
    }
