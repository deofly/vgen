from __future__ import annotations

from vgen.crypto import b64url_encode, canonical_json, sign_message

from .client import GatewayClient
from .identity_store import DeviceIdentity
from .profile import GatewayProfile, ProfileStore
from .session_store import SessionStore, StoredSession


def register_recovered_device(
    profile: GatewayProfile,
    identity: DeviceIdentity,
    *,
    device_name: str,
) -> StoredSession:
    """Use root and new-device proof-of-possession to migrate a User device."""

    client = GatewayClient(profile)
    try:
        challenge = client.request(
            "POST",
            "/api/v1/auth/device-recovery/challenges",
            json_body={
                "root_signing_public_key": identity.root_signing_public_key,
                "device_id": identity.device_id,
            },
            auth=False,
        )
        certificate = identity.certificate.to_dict()
        proof = canonical_json(
            {
                "version": 1,
                "challenge_id": challenge["challenge_id"],
                "challenge": challenge["challenge"],
                "device_id": identity.device_id,
                "device_name": device_name,
                "device_signing_public_key": certificate["payload"]["signing_public_key"],
                "device_encryption_public_key": certificate["payload"]["encryption_public_key"],
                "root_signing_public_key": identity.root_signing_public_key,
                "root_encryption_public_key": identity.root_encryption_public_key,
            }
        )
        response = client.request(
            "POST",
            "/api/v1/auth/device-recovery/complete",
            json_body={
                "challenge_id": challenge["challenge_id"],
                "root_key_id": identity.root_key_id,
                "root_signing_public_key": identity.root_signing_public_key,
                "root_encryption_public_key": identity.root_encryption_public_key,
                "device_id": identity.device_id,
                "device_name": device_name,
                "device_signing_public_key": certificate["payload"]["signing_public_key"],
                "device_encryption_public_key": certificate["payload"]["encryption_public_key"],
                "device_certificate": certificate,
                "root_signature": b64url_encode(
                    sign_message(
                        identity.root_keys.signing_private_key,
                        proof,
                        context=b"vgen-device-recovery-root-v1",
                    )
                ),
                "device_signature": b64url_encode(
                    sign_message(
                        identity.device_keys.signing_private_key,
                        proof,
                        context=b"vgen-device-recovery-device-v1",
                    )
                ),
            },
            auth=False,
        )
    finally:
        client.close()
    session = StoredSession(
        token=response["session_token"],
        expires_at=float(response["expires_at"]),
        user_id=response["user_id"],
        device_id=response["device_id"],
    )
    SessionStore().save(profile.name, session)
    ProfileStore().update_binding(
        profile.name, user_id=session.user_id, device_id=session.device_id
    )
    return session
