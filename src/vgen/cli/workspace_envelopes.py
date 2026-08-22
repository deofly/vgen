from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any

from vgen.crypto import (
    HPKE_ALGORITHM,
    DeviceKeys,
    b64url_decode,
    canonical_json,
    generate_workspace_data_key,
    sign_key_manifest,
    unwrap_workspace_key,
    verify_key_manifest,
    workspace_key_aad,
    wrap_workspace_key,
)

from .client import GatewayClient, VgenClientError
from .identity_store import DeviceIdentity
from .user_enrollment import (
    ensure_owner_self_admission,
    verify_existing_owner_admission,
    verify_recipient_bundle,
)
from .workspace_authorities import WorkspaceAuthorityStore
from .workspace_keys import WorkspaceKeyStore


class LegacyOwnerMigrationRequired(ValueError):
    """A pre-v0.3 Workspace needs an explicit, operator-approved TOFU pin."""


def require_local_workspace_owner(
    client: GatewayClient,
    identity: DeviceIdentity,
    *,
    workspace_id: str,
) -> str:
    """Require the write-once local Owner pin before any WDK mutation.

    A pre-v0.3 Owner may have neither a pin nor a signed genesis admission. In
    that case normal key mutations fail closed until the operator runs the
    explicit ``workspace owner-migrate`` trust-on-first-use command. New
    Workspaces and joined clients learn the pin from creation or the
    out-of-band Owner-signed Invite.
    """

    profile = getattr(client, "profile", None)
    user_id = str(getattr(profile, "user_id", None) or "")
    if not user_id:
        raise ValueError("a User-bound profile is required for Workspace key mutation")
    store = WorkspaceAuthorityStore()
    if store.load_owner(workspace_id) is None:
        try:
            existing = client.request(
                "GET",
                f"/api/v1/workspaces/{workspace_id}/recipient-admissions/{user_id}",
            )
        except VgenClientError as exc:
            if exc.code != 400005 and exc.status_code != 404:
                raise
            existing = None
        if existing is not None:
            if not verify_existing_owner_admission(
                existing,
                identity,
                workspace_id=workspace_id,
                owner_user_id=user_id,
            ):
                raise ValueError(
                    "Stored Workspace Owner admission does not match this local identity"
                )
            store.pin_owner(
                workspace_id=workspace_id,
                user_id=user_id,
                root_signing_public_key=identity.root_signing_public_key,
                root_key_id=identity.root_key_id,
                source="stored_owner_genesis_admission",
            )
        else:
            raise LegacyOwnerMigrationRequired(
                "Workspace Owner pin and signed genesis admission are missing; "
                "run `vgen workspace owner-migrate` and review the legacy TOFU warning"
            )
    store.require_owner_identity(
        workspace_id=workspace_id,
        user_id=user_id,
        root_signing_public_key=identity.root_signing_public_key,
        root_key_id=identity.root_key_id,
    )
    return user_id


def migrate_legacy_workspace_owner(
    client: GatewayClient,
    identity: DeviceIdentity,
    *,
    workspace_id: str,
) -> dict[str, Any]:
    """Explicitly establish the one-time pin for a pre-v0.3 Owner Workspace.

    The CLI owns the dangerous confirmation UI. This helper performs the
    mutation only after that confirmation and never replaces an existing pin.
    """

    profile = getattr(client, "profile", None)
    user_id = str(getattr(profile, "user_id", None) or "")
    if not user_id:
        raise ValueError("a User-bound profile is required for Workspace Owner migration")
    store = WorkspaceAuthorityStore()
    existing_pin = store.load_owner(workspace_id)
    if existing_pin is not None:
        store.require_owner_identity(
            workspace_id=workspace_id,
            user_id=user_id,
            root_signing_public_key=identity.root_signing_public_key,
            root_key_id=identity.root_key_id,
        )
        return {
            "workspace_id": workspace_id,
            "owner_user_id": user_id,
            "owner_root_key_id": identity.root_key_id,
            "migrated": False,
            "source": existing_pin.source,
        }

    workspaces = client.request("GET", "/api/v1/workspaces")
    workspace = next(
        (
            item
            for item in workspaces
            if isinstance(item, dict) and str(item.get("id")) == workspace_id
        ),
        None,
    )
    if workspace is None or str(workspace.get("owner_user_id")) != user_id:
        raise ValueError(
            "Gateway does not report this authenticated User as the Workspace Owner"
        )

    # Persist the immutable, Owner-root-signed genesis admission before the
    # local pin. If local pin storage fails, a retry can verify this admission
    # cryptographically and complete without another TOFU decision.
    ensure_owner_self_admission(
        client,
        identity,
        workspace_id=workspace_id,
        owner_user_id=user_id,
    )
    pin = store.pin_owner(
        workspace_id=workspace_id,
        user_id=user_id,
        root_signing_public_key=identity.root_signing_public_key,
        root_key_id=identity.root_key_id,
        source="explicit_legacy_owner_tofu",
    )
    return {
        "workspace_id": workspace_id,
        "owner_user_id": user_id,
        "owner_root_key_id": identity.root_key_id,
        "migrated": True,
        "source": pin.source,
    }


def _verify_received_envelope(
    item: dict[str, Any],
    *,
    identity: DeviceIdentity,
    user_id: str,
    workspace_id: str,
    recipient_type: str,
    recipient_id: str,
    authority_store: WorkspaceAuthorityStore,
) -> str:
    """Validate the signed envelope before any key reaches the OS Keychain.

    Envelopes signed by this User are pinned to the locally derived root. A
    cross-user Owner/Admin signature must match a write-once local authority
    pin learned from the complete out-of-band Invite fragment or an explicit
    authority-pin operation. Gateway response fields can only be compared with
    that pin; they never create or replace it.
    """

    try:
        signed = item["signed_manifest"]
        manifest = signed["manifest"]
        signer_public = str(item["signer_root_signing_public_key"])
        signer_user_id = str(item["signer_user_id"])
        envelope = item["envelope"]
        valid_fields = (
            manifest.get("version") == 1
            and manifest.get("kind") == "vgen-workspace-key-envelope"
            and manifest.get("workspace_id") == workspace_id
            and manifest.get("recipient_type") == recipient_type
            and manifest.get("recipient_id") == recipient_id
            and manifest.get("key_version") == int(item["key_version"])
            and manifest.get("algorithm") == HPKE_ALGORITHM
            and item.get("algorithm") == HPKE_ALGORITHM
            and manifest.get("envelope_sha256")
            == hashlib.sha256(canonical_json(envelope)).hexdigest()
            and manifest.get("signer_root_key_id") == signed.get("signer_key_id")
            and verify_key_manifest(signed, b64url_decode(signer_public, expected_length=32))
        )
    except (KeyError, TypeError, ValueError):
        valid_fields = False
        signer_public = ""
        signer_user_id = ""
    if not valid_fields:
        raise ValueError("Workspace key envelope signature or binding is invalid")
    if signer_public == identity.root_signing_public_key and signer_user_id == user_id:
        return "local_user_root"
    authority_store.require(
        workspace_id=workspace_id,
        user_id=signer_user_id,
        presented_root_signing_public_key=signer_public,
        presented_root_key_id=str(signed.get("signer_key_id")),
    )
    return "pinned_workspace_authority"


def _signed_grant(
    *,
    identity: DeviceIdentity,
    workspace_id: str,
    recipient_type: str,
    recipient_id: str,
    key_version: int,
    envelope: dict[str, str],
    recipient_public_key_sha256: str,
    recipient_admission_sha256: str,
    recipient_binding_digest: str,
    rotation_id: str | None = None,
    recipient_set_digest: str | None = None,
) -> dict[str, Any]:
    manifest = {
        "version": 1,
        "kind": "vgen-workspace-key-envelope",
        "workspace_id": workspace_id,
        "recipient_type": recipient_type,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "algorithm": HPKE_ALGORITHM,
        "envelope_sha256": hashlib.sha256(canonical_json(envelope)).hexdigest(),
        "recipient_public_key_sha256": recipient_public_key_sha256,
        "recipient_admission_sha256": recipient_admission_sha256,
        "recipient_binding_digest": recipient_binding_digest,
        "signer_root_key_id": identity.root_key_id,
        "issued_at": int(time.time()),
    }
    if rotation_id is not None:
        manifest["rotation_id"] = rotation_id
        manifest["recipient_set_digest"] = recipient_set_digest
    return sign_key_manifest(identity.root_keys, manifest)


def grant_workspace_key(
    client: GatewayClient,
    identity: DeviceIdentity,
    *,
    workspace_id: str,
    recipient_type: str,
    recipient_id: str,
    key_version: int,
    workspace_key: bytes,
) -> dict[str, Any]:
    local_user_id = require_local_workspace_owner(
        client, identity, workspace_id=workspace_id
    )
    ensure_owner_self_admission(
        client,
        identity,
        workspace_id=workspace_id,
        owner_user_id=local_user_id,
    )
    recipient = client.request(
        "GET",
        f"/api/v1/workspaces/{workspace_id}/key-recipients/{recipient_type}/{recipient_id}",
    )
    if int(recipient["key_version"]) != key_version:
        raise ValueError("recipient expects a different Workspace key version")
    binding = verify_recipient_bundle(
        recipient,
        identity,
        workspace_id=workspace_id,
        owner_user_id=local_user_id,
        expected_recipient_type=recipient_type,
        expected_recipient_id=recipient_id,
    )
    aad = workspace_key_aad(
        workspace_id=workspace_id,
        recipient_type=recipient_type,
        recipient_id=recipient_id,
        key_version=key_version,
        recipient_binding_digest=binding["recipient_binding_digest"],
    )
    envelope = wrap_workspace_key(
        b64url_decode(binding["encryption_public_key"], expected_length=32),
        workspace_key,
        aad=aad,
    ).to_dict()
    signed = _signed_grant(
        identity=identity,
        workspace_id=workspace_id,
        recipient_type=recipient_type,
        recipient_id=recipient_id,
        key_version=key_version,
        envelope=envelope,
        recipient_public_key_sha256=binding["recipient_key_sha256"],
        recipient_admission_sha256=binding["admission_digest"],
        recipient_binding_digest=binding["recipient_binding_digest"],
    )
    envelope_digest = hashlib.sha256(canonical_json(envelope)).hexdigest()
    return client.request(
        "POST",
        f"/api/v1/workspaces/{workspace_id}/key-envelopes",
        json_body={
            "recipient_type": recipient_type,
            "recipient_id": recipient_id,
            "key_version": key_version,
            "algorithm": HPKE_ALGORITHM,
            "envelope": envelope,
            "signed_manifest": signed,
        },
        idempotency_key=(
            f"workspace-key:{workspace_id}:v{key_version}:{recipient_type}:"
            f"{recipient_id}:{envelope_digest[:20]}"
        ),
    )


def initialize_workspace_keys(
    client: GatewayClient,
    identity: DeviceIdentity,
    workspace: dict[str, Any],
    *,
    store: WorkspaceKeyStore | None = None,
) -> list[dict[str, Any]]:
    key_store = store or WorkspaceKeyStore()
    workspace_id = str(workspace["id"])
    key_version = int(workspace.get("key_version", 1))
    owner_user_id = str(workspace["owner_user_id"])
    ensure_owner_self_admission(
        client,
        identity,
        workspace_id=workspace_id,
        owner_user_id=owner_user_id,
    )
    workspace_key = key_store.create(workspace_id, key_version)
    return [
        grant_workspace_key(
            client,
            identity,
            workspace_id=workspace_id,
            recipient_type="user_recovery",
            recipient_id=owner_user_id,
            key_version=key_version,
            workspace_key=workspace_key,
        ),
        grant_workspace_key(
            client,
            identity,
            workspace_id=workspace_id,
            recipient_type="device",
            recipient_id=identity.device_id,
            key_version=key_version,
            workspace_key=workspace_key,
        ),
    ]


def rotate_workspace_key(
    client: GatewayClient,
    identity: DeviceIdentity,
    *,
    workspace_id: str,
    expected_key_version: int | None = None,
    store: WorkspaceKeyStore | None = None,
) -> dict[str, Any]:
    """Create, wrap and atomically activate the next Workspace Data Key.

    The plaintext key remains in memory until Gateway confirms that every
    active recipient envelope was stored and the version was switched. This
    prevents a failed or competing rotation from overwriting a locally cached
    key for an already-active version.
    """

    local_user_id = require_local_workspace_owner(
        client, identity, workspace_id=workspace_id
    )
    ensure_owner_self_admission(
        client,
        identity,
        workspace_id=workspace_id,
        owner_user_id=local_user_id,
    )
    snapshot = client.request("GET", f"/api/v1/workspaces/{workspace_id}/key-rotation/recipients")
    current_version = int(snapshot["current_key_version"])
    new_key_version = int(snapshot["next_key_version"])
    if expected_key_version is not None and current_version != expected_key_version:
        raise ValueError("Workspace key version changed; fetch a new rotation snapshot")
    if new_key_version != current_version + 1:
        raise ValueError("Gateway returned a non-contiguous Workspace key version")
    raw_recipients = snapshot.get("recipients")
    if not isinstance(raw_recipients, list) or not raw_recipients:
        raise ValueError("Gateway returned no authorized Workspace key recipients")
    recipients: list[dict[str, Any]] = []
    pairs: set[tuple[str, str]] = set()
    for raw in raw_recipients:
        if not isinstance(raw, dict):
            raise ValueError("Gateway returned an invalid Workspace key recipient")
        recipient = dict(raw)
        recipient["recipient_type"] = str(raw.get("recipient_type", ""))
        recipient["recipient_id"] = str(raw.get("recipient_id", ""))
        pair = (recipient["recipient_type"], recipient["recipient_id"])
        if recipient["recipient_type"] not in {"user_recovery", "device", "service"} or (
            not recipient["recipient_id"] or pair in pairs
        ):
            raise ValueError("Gateway returned an invalid Workspace key recipient set")
        verify_recipient_bundle(
            recipient,
            identity,
            workspace_id=workspace_id,
            owner_user_id=local_user_id,
            expected_recipient_type=recipient["recipient_type"],
            expected_recipient_id=recipient["recipient_id"],
        )
        pairs.add(pair)
        recipients.append(recipient)
    recipients.sort(key=lambda value: (value["recipient_type"], value["recipient_id"]))
    recipient_set_digest = hashlib.sha256(canonical_json(recipients)).hexdigest()
    if snapshot.get("recipient_set_digest") != recipient_set_digest:
        raise ValueError("Workspace key recipient snapshot digest is invalid")

    rotation_id = "wkr_" + secrets.token_urlsafe(18)
    workspace_key = generate_workspace_data_key()
    grants: list[dict[str, Any]] = []
    for recipient in recipients:
        recipient_type = recipient["recipient_type"]
        recipient_id = recipient["recipient_id"]
        binding = verify_recipient_bundle(
            recipient,
            identity,
            workspace_id=workspace_id,
            owner_user_id=local_user_id,
            expected_recipient_type=recipient_type,
            expected_recipient_id=recipient_id,
        )
        aad = workspace_key_aad(
            workspace_id=workspace_id,
            recipient_type=recipient_type,
            recipient_id=recipient_id,
            key_version=new_key_version,
            recipient_binding_digest=binding["recipient_binding_digest"],
        )
        envelope = wrap_workspace_key(
            b64url_decode(binding["encryption_public_key"], expected_length=32),
            workspace_key,
            aad=aad,
        ).to_dict()
        grants.append(
            {
                "recipient_type": recipient_type,
                "recipient_id": recipient_id,
                "key_version": new_key_version,
                "algorithm": HPKE_ALGORITHM,
                "envelope": envelope,
                "signed_manifest": _signed_grant(
                    identity=identity,
                    workspace_id=workspace_id,
                    recipient_type=recipient_type,
                    recipient_id=recipient_id,
                    key_version=new_key_version,
                    envelope=envelope,
                    recipient_public_key_sha256=binding["recipient_key_sha256"],
                    recipient_admission_sha256=binding["admission_digest"],
                    recipient_binding_digest=binding["recipient_binding_digest"],
                    rotation_id=rotation_id,
                    recipient_set_digest=recipient_set_digest,
                ),
            }
        )

    result = client.request(
        "POST",
        f"/api/v1/workspaces/{workspace_id}/key-rotations",
        json_body={
            "rotation_id": rotation_id,
            "expected_key_version": current_version,
            "new_key_version": new_key_version,
            "recipient_set_digest": recipient_set_digest,
            "envelopes": grants,
        },
        idempotency_key=f"workspace-key-rotation:{workspace_id}:{rotation_id}",
    )
    if int(result.get("key_version", 0)) != new_key_version:
        raise ValueError("Gateway did not confirm the requested Workspace key version")
    (store or WorkspaceKeyStore()).save(workspace_id, new_key_version, workspace_key)
    return {
        **result,
        "local_key_saved": True,
    }


def sync_workspace_key(
    client: GatewayClient,
    identity: DeviceIdentity,
    *,
    workspace_id: str,
    user_id: str,
    key_version: int | None = None,
    store: WorkspaceKeyStore | None = None,
    authority_store: WorkspaceAuthorityStore | None = None,
) -> dict[str, Any]:
    key_store = store or WorkspaceKeyStore()
    local_authorities = authority_store or WorkspaceAuthorityStore()
    local_authorities.pin(
        workspace_id=workspace_id,
        user_id=user_id,
        root_signing_public_key=identity.root_signing_public_key,
        root_key_id=identity.root_key_id,
        source="local_user_root",
    )
    candidates = (
        ("device", identity.device_id, identity.device_keys.encryption_private_key),
        ("user_recovery", user_id, identity.root_keys.encryption_private_key),
    )
    selected: tuple[str, str, Any, dict[str, Any]] | None = None
    for recipient_type, recipient_id, private_key in candidates:
        try:
            response = client.request(
                "GET",
                f"/api/v1/workspaces/{workspace_id}/key-envelopes/{recipient_type}/{recipient_id}",
                params={"key_version": key_version} if key_version else None,
            )
        except VgenClientError as exc:
            if exc.code in {400002, 600001} or exc.status_code == 404:
                continue
            raise
        items = response.get("items", [])
        if items:
            selected = (recipient_type, recipient_id, private_key, items[0])
            break
    if selected is None:
        raise ValueError("no decryptable Workspace key envelope is available for this user/device")
    recipient_type, recipient_id, private_key, item = selected
    version = int(item["key_version"])
    aad = workspace_key_aad(
        workspace_id=workspace_id,
        recipient_type=recipient_type,
        recipient_id=recipient_id,
        key_version=version,
        recipient_binding_digest=(
            str(item.get("signed_manifest", {}).get("manifest", {}).get("recipient_binding_digest"))
            if item.get("signed_manifest", {}).get("manifest", {}).get(
                "recipient_binding_digest"
            )
            else None
        ),
    )
    trust_source = _verify_received_envelope(
        item,
        identity=identity,
        user_id=user_id,
        workspace_id=workspace_id,
        recipient_type=recipient_type,
        recipient_id=recipient_id,
        authority_store=local_authorities,
    )
    workspace_key = unwrap_workspace_key(private_key, item["envelope"], aad=aad)
    key_store.save(workspace_id, version, workspace_key)
    return {
        "workspace_id": workspace_id,
        "key_version": version,
        "source": recipient_type,
        "signer_trust": trust_source,
        "device_envelope_created": False,
        "historical_version": False,
    }


def sync_service_workspace_key(
    client: GatewayClient,
    service_keys: DeviceKeys,
    *,
    workspace_id: str,
    service_id: str,
    key_version: int | None = None,
    store: WorkspaceKeyStore | None = None,
    authority_store: WorkspaceAuthorityStore | None = None,
) -> dict[str, Any]:
    """Import an admin-signed WDK envelope addressed to one API Service.

    A Service never falls back to a User recovery or Device envelope.  This
    keeps its decryption authority constrained to the public key enrolled for
    that Service principal.
    """

    response = client.request(
        "GET",
        f"/api/v1/workspaces/{workspace_id}/key-envelopes/service/{service_id}",
        params={"key_version": key_version} if key_version else None,
    )
    items = response.get("items", [])
    if not items:
        raise ValueError("no Workspace key envelope is available for this Service")
    item = items[0]
    try:
        signed = item["signed_manifest"]
        manifest = signed["manifest"]
        envelope = item["envelope"]
        version = int(item["key_version"])
        signer_public = b64url_decode(
            str(item["signer_root_signing_public_key"]), expected_length=32
        )
        valid = (
            manifest.get("version") == 1
            and manifest.get("kind") == "vgen-workspace-key-envelope"
            and manifest.get("workspace_id") == workspace_id
            and manifest.get("recipient_type") == "service"
            and manifest.get("recipient_id") == service_id
            and manifest.get("key_version") == version
            and manifest.get("algorithm") == HPKE_ALGORITHM
            and item.get("algorithm") == HPKE_ALGORITHM
            and manifest.get("envelope_sha256")
            == hashlib.sha256(canonical_json(envelope)).hexdigest()
            and manifest.get("signer_root_key_id") == signed.get("signer_key_id")
            and verify_key_manifest(signed, signer_public)
        )
    except (KeyError, TypeError, ValueError):
        valid = False
        version = 0
        envelope = {}
    if not valid:
        raise ValueError("Workspace key envelope signature or Service binding is invalid")
    try:
        (authority_store or WorkspaceAuthorityStore()).require(
            workspace_id=workspace_id,
            user_id=str(item["signer_user_id"]),
            presented_root_signing_public_key=str(item["signer_root_signing_public_key"]),
            presented_root_key_id=str(signed.get("signer_key_id")),
        )
    except (KeyError, TypeError) as exc:
        raise ValueError("Workspace key envelope signer binding is invalid") from exc
    aad = workspace_key_aad(
        workspace_id=workspace_id,
        recipient_type="service",
        recipient_id=service_id,
        key_version=version,
    )
    workspace_key = unwrap_workspace_key(
        service_keys.encryption_private_key,
        envelope,
        aad=aad,
    )
    (store or WorkspaceKeyStore()).save(workspace_id, version, workspace_key)
    return {
        "workspace_id": workspace_id,
        "key_version": version,
        "source": "service",
        "signer_trust": "pinned_workspace_authority",
    }
