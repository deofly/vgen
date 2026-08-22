from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import keyring

from vgen.crypto import (
    IdentityKeys,
    b64url_decode,
    b64url_encode,
    root_signing_key_id,
    sign_key_manifest,
    verify_key_manifest,
)


class WorkspaceAuthorityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class WorkspaceAuthorityPin:
    workspace_id: str
    user_id: str
    root_signing_public_key: str
    root_key_id: str
    source: str


@dataclass(frozen=True, slots=True)
class PinnedInvite:
    invite_id: str
    secret: str
    authority: WorkspaceAuthorityPin


class WorkspaceAuthorityStore:
    """Device-local trust anchors for Workspace Owner/Admin root keys.

    Pins are write-once per Workspace/User pair. Gateway responses can be
    compared with a pin, but are never allowed to create or replace one.
    """

    SERVICE = "vgen.workspace-authority.v1"
    OWNER_SERVICE = "vgen.workspace-owner-authority.v1"

    def __init__(self, backend=None) -> None:  # type: ignore[no-untyped-def]
        self.backend = backend or keyring

    @staticmethod
    def _username(workspace_id: str, user_id: str) -> str:
        if not workspace_id or not user_id:
            raise ValueError("Workspace and authority User IDs are required")
        return f"{workspace_id}:{user_id}"

    def load(self, workspace_id: str, user_id: str) -> WorkspaceAuthorityPin | None:
        raw = self.backend.get_password(self.SERVICE, self._username(workspace_id, user_id))
        if not raw:
            return None
        try:
            value = json.loads(raw)
            pin = WorkspaceAuthorityPin(**value)
            public_key = b64url_decode(pin.root_signing_public_key, expected_length=32)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise WorkspaceAuthorityError("stored Workspace authority pin is corrupt") from exc
        if (
            pin.workspace_id != workspace_id
            or pin.user_id != user_id
            or root_signing_key_id(public_key) != pin.root_key_id
        ):
            raise WorkspaceAuthorityError("stored Workspace authority pin binding is invalid")
        return pin

    def pin(
        self,
        *,
        workspace_id: str,
        user_id: str,
        root_signing_public_key: str,
        root_key_id: str | None = None,
        source: str,
    ) -> WorkspaceAuthorityPin:
        public_key = b64url_decode(root_signing_public_key, expected_length=32)
        derived_key_id = root_signing_key_id(public_key)
        if root_key_id is not None and root_key_id != derived_key_id:
            raise WorkspaceAuthorityError("Workspace authority root key ID does not match its key")
        pin = WorkspaceAuthorityPin(
            workspace_id=workspace_id,
            user_id=user_id,
            root_signing_public_key=root_signing_public_key,
            root_key_id=derived_key_id,
            source=source,
        )
        existing = self.load(workspace_id, user_id)
        if existing is not None:
            if (
                existing.root_signing_public_key != pin.root_signing_public_key
                or existing.root_key_id != pin.root_key_id
            ):
                raise WorkspaceAuthorityError(
                    "Workspace authority is already pinned to a different root key"
                )
            return existing
        self.backend.set_password(
            self.SERVICE,
            self._username(workspace_id, user_id),
            json.dumps(asdict(pin), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
        return pin

    def require(
        self,
        *,
        workspace_id: str,
        user_id: str,
        presented_root_signing_public_key: str,
        presented_root_key_id: str | None = None,
    ) -> WorkspaceAuthorityPin:
        pin = self.load(workspace_id, user_id)
        if pin is None:
            raise WorkspaceAuthorityError(
                "Workspace authority is not pinned locally; import it through a trusted invite "
                "or `vgen workspace authority-pin`"
            )
        if pin.root_signing_public_key != presented_root_signing_public_key:
            raise WorkspaceAuthorityError("Gateway substituted the pinned Workspace authority key")
        if presented_root_key_id is not None and pin.root_key_id != presented_root_key_id:
            raise WorkspaceAuthorityError("Workspace authority key ID does not match the local pin")
        return pin

    def load_owner(self, workspace_id: str) -> WorkspaceAuthorityPin | None:
        """Load the single write-once Owner root pin for a Workspace."""

        raw = self.backend.get_password(self.OWNER_SERVICE, workspace_id)
        if not raw:
            return None
        try:
            value = json.loads(raw)
            pin = WorkspaceAuthorityPin(**value)
            public_key = b64url_decode(pin.root_signing_public_key, expected_length=32)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise WorkspaceAuthorityError("stored Workspace Owner pin is corrupt") from exc
        if (
            pin.workspace_id != workspace_id
            or root_signing_key_id(public_key) != pin.root_key_id
        ):
            raise WorkspaceAuthorityError("stored Workspace Owner pin binding is invalid")
        return pin

    def pin_owner(
        self,
        *,
        workspace_id: str,
        user_id: str,
        root_signing_public_key: str,
        root_key_id: str | None = None,
        source: str,
    ) -> WorkspaceAuthorityPin:
        """Pin the unique Workspace Owner; it can never be silently replaced."""

        public_key = b64url_decode(root_signing_public_key, expected_length=32)
        derived_key_id = root_signing_key_id(public_key)
        if root_key_id is not None and root_key_id != derived_key_id:
            raise WorkspaceAuthorityError("Workspace Owner root key ID does not match its key")
        pin = WorkspaceAuthorityPin(
            workspace_id=workspace_id,
            user_id=user_id,
            root_signing_public_key=root_signing_public_key,
            root_key_id=derived_key_id,
            source=source,
        )
        existing = self.load_owner(workspace_id)
        if existing is not None:
            if (
                existing.user_id != pin.user_id
                or existing.root_signing_public_key != pin.root_signing_public_key
                or existing.root_key_id != pin.root_key_id
            ):
                raise WorkspaceAuthorityError(
                    "Workspace Owner is already pinned to a different User or root key"
                )
            return existing
        self.backend.set_password(
            self.OWNER_SERVICE,
            workspace_id,
            json.dumps(asdict(pin), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
        # Keep the older per-User pin for envelope verification compatibility.
        self.pin(
            workspace_id=workspace_id,
            user_id=user_id,
            root_signing_public_key=root_signing_public_key,
            root_key_id=derived_key_id,
            source=source,
        )
        return pin

    def require_owner_identity(
        self,
        *,
        workspace_id: str,
        user_id: str,
        root_signing_public_key: str,
        root_key_id: str,
    ) -> WorkspaceAuthorityPin:
        pin = self.load_owner(workspace_id)
        if pin is None:
            raise WorkspaceAuthorityError(
                "Workspace Owner is not pinned locally; use the signed Owner Invite or "
                "complete the legacy Owner migration first"
            )
        if (
            pin.user_id != user_id
            or pin.root_signing_public_key != root_signing_public_key
            or pin.root_key_id != root_key_id
        ):
            raise WorkspaceAuthorityError(
                "This local identity is not the pinned Workspace Owner"
            )
        return pin


def decorate_invite_uri(
    invite_uri: str,
    *,
    workspace_id: str,
    issuer_user_id: str,
    identity: IdentityKeys,
) -> str:
    parsed = urlsplit(invite_uri)
    if parsed.scheme != "vgen" or parsed.netloc != "join" or not parsed.path.strip("/"):
        raise WorkspaceAuthorityError("Gateway returned an invalid Invite URI")
    invite_id = parsed.path.strip("/")
    secret = parsed.fragment
    if len(secret) < 16:
        raise WorkspaceAuthorityError("Gateway returned an incomplete Invite URI")
    root_public = b64url_encode(identity.signing_public_bytes())
    manifest = {
        "version": 1,
        "kind": "vgen-workspace-authority-invite",
        "invite_id": invite_id,
        "invite_secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        "workspace_id": workspace_id,
        "issuer_user_id": issuer_user_id,
        "issuer_root_signing_public_key": root_public,
        "issuer_root_key_id": identity.root_key_id,
    }
    signed = sign_key_manifest(identity, manifest)
    fragment = urlencode(
        {
            "secret": secret,
            "authority": b64url_encode(
                json.dumps(
                    signed, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).encode()
            ),
        }
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", fragment))


def parse_pinned_invite_uri(value: str) -> PinnedInvite:
    try:
        parsed = urlsplit(value.strip())
        values = parse_qs(parsed.fragment, strict_parsing=True)
        secret_values = values.get("secret", [])
        authority_values = values.get("authority", [])
        if (
            parsed.scheme != "vgen"
            or parsed.netloc != "join"
            or len(secret_values) != 1
            or len(authority_values) != 1
        ):
            raise ValueError
        invite_id = parsed.path.strip("/")
        secret = secret_values[0]
        signed = json.loads(b64url_decode(authority_values[0]))
        manifest = signed["manifest"]
        root_public_text = str(manifest["issuer_root_signing_public_key"])
        root_public = b64url_decode(root_public_text, expected_length=32)
        valid = (
            bool(invite_id)
            and len(secret) >= 16
            and manifest.get("version") == 1
            and manifest.get("kind") == "vgen-workspace-authority-invite"
            and manifest.get("invite_id") == invite_id
            and manifest.get("invite_secret_sha256") == hashlib.sha256(secret.encode()).hexdigest()
            and manifest.get("issuer_root_key_id") == root_signing_key_id(root_public)
            and signed.get("signer_key_id") == manifest.get("issuer_root_key_id")
            and verify_key_manifest(signed, root_public)
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise WorkspaceAuthorityError(
            "Invite URI has no valid out-of-band Workspace authority pin"
        ) from exc
    if not valid:
        raise WorkspaceAuthorityError("Invite URI has no valid out-of-band Workspace authority pin")
    return PinnedInvite(
        invite_id=invite_id,
        secret=secret,
        authority=WorkspaceAuthorityPin(
            workspace_id=str(manifest["workspace_id"]),
            user_id=str(manifest["issuer_user_id"]),
            root_signing_public_key=root_public_text,
            root_key_id=str(manifest["issuer_root_key_id"]),
            source="signed_invite_fragment",
        ),
    )
