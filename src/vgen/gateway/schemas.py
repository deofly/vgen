"""Pydantic wire validation for Gateway v1 HTTP routes."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .public_metadata import (
    PublicMetadataError,
    validate_artifact_media_metadata,
    validate_public_requirements,
    validate_reported_artifact_media_metadata,
)

_WORKFLOW_RELEASE_REF_PATTERN = (
    r"^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*@"
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class HealthCounts(WireModel):
    users: int = Field(ge=0)
    workspaces: int = Field(ge=0)
    tasks: int = Field(ge=0)
    workers_total: int = Field(ge=0)
    workers_active: int = Field(ge=0)
    workers_online: int = Field(ge=0)
    workers_revoked: int = Field(ge=0)


class HealthResponse(WireModel):
    ok: Literal[True]


class StatusResponse(WireModel):
    ok: Literal[True]
    schema_version: int = Field(ge=1)
    journal_mode: str
    counts: HealthCounts


class BootstrapRequest(WireModel):
    bootstrap_code: str = Field(min_length=1)
    display_name: str = Field(default="Gateway Operator", min_length=1, max_length=120)
    root_key_id: str | None = None
    root_signing_public_key: str = Field(min_length=16)
    root_encryption_public_key: str = Field(min_length=16)
    device_id: str
    device_name: str = Field(default="default", min_length=1, max_length=120)
    device_signing_public_key: str = Field(min_length=16)
    device_encryption_public_key: str = Field(min_length=16)
    device_certificate: dict[str, Any]


class ChallengeRequest(WireModel):
    device_id: str | None = None
    worker_id: str | None = None
    service_id: str | None = None
    principal_type: Literal["device", "service", "worker"] = "device"


class SessionRequest(WireModel):
    device_id: str | None = None
    worker_id: str | None = None
    service_id: str | None = None
    principal_type: Literal["device", "service", "worker"] = "device"
    challenge_id: str
    signature: str
    device_certificate: dict[str, Any] | None = None
    root_key_id: str | None = None
    root_signing_public_key: str | None = None
    root_encryption_public_key: str | None = None


class UserEnrollmentClaim(WireModel):
    version: Literal[1]
    kind: Literal["vgen-user-enrollment-claim"]
    invite_id: str
    display_name: str = Field(default="VGen User", min_length=1, max_length=120)
    root_key_id: str = Field(min_length=16, max_length=128)
    root_signing_public_key: str = Field(min_length=16)
    root_encryption_public_key: str = Field(min_length=16)
    device_id: str
    device_name: str = Field(default="default", min_length=1, max_length=120)
    device_signing_public_key: str = Field(min_length=16)
    device_encryption_public_key: str = Field(min_length=16)
    device_certificate: dict[str, Any]


class UserEnrollmentRequest(WireModel):
    invite_id: str
    secret: str = Field(
        min_length=16,
        json_schema_extra={"writeOnly": True, "format": "password"},
    )
    claim: UserEnrollmentClaim
    proof_signature: str = Field(min_length=16)


class DeviceEnrollmentRequest(WireModel):
    invite_id: str
    secret: str = Field(min_length=16)
    root_key_id: str | None = None
    root_signing_public_key: str = Field(min_length=16)
    root_encryption_public_key: str = Field(min_length=16)
    device_id: str
    device_name: str = Field(default="default", min_length=1, max_length=120)
    device_signing_public_key: str | None = Field(default=None, min_length=16)
    device_encryption_public_key: str | None = Field(default=None, min_length=16)
    device_certificate: dict[str, Any]
    proof_signature: str = Field(min_length=16)


class DeviceRecoveryChallengeRequest(WireModel):
    root_signing_public_key: str = Field(min_length=16)
    device_id: str


class DeviceRecoveryCompleteRequest(WireModel):
    challenge_id: str
    root_key_id: str | None = None
    root_signing_public_key: str = Field(min_length=16)
    root_encryption_public_key: str = Field(min_length=16)
    device_id: str
    device_name: str = Field(default="recovered-device", min_length=1, max_length=120)
    device_signing_public_key: str = Field(min_length=16)
    device_encryption_public_key: str = Field(min_length=16)
    device_certificate: dict[str, Any]
    root_signature: str = Field(min_length=16)
    device_signature: str = Field(min_length=16)


class WorkspaceCreate(WireModel):
    name: str = Field(min_length=1, max_length=120)
    founder_broker_id: str | None = None
    enrollment_policy: dict[str, Literal["apply_approval", "closed"]] = Field(
        default_factory=lambda: {
            "workspace_member": "apply_approval",
            "service": "closed",
            "broker_device": "closed",
            "worker_allocation": "closed",
        }
    )


class PoolCreate(WireModel):
    name: str = Field(min_length=1, max_length=120)
    policy: dict[str, Any] = Field(default_factory=dict)


class BrokerCreate(WireModel):
    name: str = Field(min_length=1, max_length=120)
    device_id: str | None = None


class BrokerDeviceAttach(WireModel):
    device_id: str


class BrokerHeartbeat(WireModel):
    broker_id: str
    status: Literal["online"] = "online"
    runtime_version: str | None = Field(default=None, min_length=1, max_length=120)
    protocol_version: str = Field(default="1", min_length=1, max_length=32)
    build_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,64}$")
    journal_pending: int = Field(default=0, ge=0)


class CommandComplete(WireModel):
    succeeded: bool = True
    result: dict[str, Any] = Field(default_factory=dict)


class InviteCreate(WireModel):
    # Worker allocation is deliberately not an Invite credential.  A Worker
    # owner must offer an already registered Worker and a Workspace admin must
    # approve the resulting allocation proof.
    kind: Literal["user", "broker_device", "service", "workspace_member"]
    method: Literal["direct_invite", "invite_approval"] = "invite_approval"
    scopes: list[str] = Field(default_factory=list)
    relationship: str | None = None
    subject_key_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    ttl_seconds: int = Field(default=1800, ge=60, le=604800)


class ApplicationCreate(WireModel):
    application_id: str
    workspace_id: str
    pool_id: str | None = None
    kind: Literal["workspace_member"]
    relationship: str | None = None
    claim: UserEnrollmentClaim
    proof_signature: str = Field(min_length=16)


class InviteClaim(WireModel):
    invite_id: str
    secret: str = Field(
        min_length=16,
        json_schema_extra={"writeOnly": True, "format": "password"},
    )
    claim: UserEnrollmentClaim
    proof_signature: str = Field(min_length=16)


class EnrollmentDecision(WireModel):
    approve: bool
    signed_admission: dict[str, Any] | None = None

    @model_validator(mode="after")
    def approval_material_is_consistent(self) -> EnrollmentDecision:
        if not self.approve and self.signed_admission is not None:
            raise ValueError("rejecting an enrollment must not include admission material")
        return self


class WorkspaceRecipientAdmissionCreate(WireModel):
    enrollment_id: str | None = None
    signed_admission: dict[str, Any]


class ServiceEnrollmentRequest(WireModel):
    invite_id: str
    secret: str = Field(min_length=16)
    name: str = Field(min_length=1, max_length=120)
    signing_public_key: str = Field(min_length=16)
    encryption_public_key: str = Field(min_length=16)
    proof_signature: str = Field(min_length=16)


class WorkspaceKeyEnvelopeGrant(WireModel):
    recipient_type: Literal["user_recovery", "device", "service"]
    recipient_id: str
    key_version: int = Field(default=1, ge=1)
    algorithm: str = Field(min_length=1, max_length=120)
    envelope: dict[str, str]
    signed_manifest: dict[str, Any]


class WorkspaceKeyRotationCreate(WireModel):
    rotation_id: str = Field(pattern=r"^wkr_[A-Za-z0-9_-]{16,128}$")
    expected_key_version: int = Field(ge=1)
    new_key_version: int = Field(ge=2)
    recipient_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    envelopes: list[WorkspaceKeyEnvelopeGrant] = Field(min_length=1, max_length=4096)


class WorkerCreate(WireModel):
    name: str = Field(min_length=1, max_length=120)
    manager_broker_id: str | None = None
    signing_public_key: str = Field(min_length=16)
    encryption_public_key: str = Field(min_length=16)
    certificate: str = Field(min_length=1, max_length=16_384)
    executor_type: str = Field(min_length=1, max_length=120)
    executor_version: str = Field(default="", max_length=120)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    capacity: int = Field(default=1, ge=1, le=64)


class GatewayProtocolFeatures(WireModel):
    capability_install_spec_version: Literal[2]
    node_pack_install_spec_version: Literal[1]


class WorkerWorkflowReadiness(WireModel):
    workflow_ref: str
    workflow_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    state: Literal[
        "ready",
        "missing_models",
        "missing_nodes",
        "node_probe_unavailable",
        "executor_incompatible",
        "runtime_incompatible",
        "insufficient_vram",
        "insufficient_ram",
    ]
    missing_model_digests: list[str] = Field(default_factory=list)
    missing_node_classes: list[str] = Field(default_factory=list)


class WorkerExecutorCapabilityFacts(WireModel):
    capability_schema_version: Literal[2] | None = None
    model_digests: list[str] = Field(default_factory=list)
    node_pack_digests: list[str] = Field(default_factory=list)
    workflow_readiness: list[WorkerWorkflowReadiness] = Field(default_factory=list)
    ready_workflow_digests: list[str] = Field(default_factory=list)
    vram_bytes: int | None = Field(default=None, ge=0)
    ram_bytes: int | None = Field(default=None, ge=0)
    runtime_version: str | None = None


class WorkerExecutorCapability(WireModel):
    type: str
    version: str | None = None
    payload_formats: list[str] = Field(default_factory=list)
    operations: list[str] = Field(default_factory=list)
    max_concurrency: int = Field(default=1, ge=1, le=64)
    capabilities: WorkerExecutorCapabilityFacts = Field(
        default_factory=WorkerExecutorCapabilityFacts
    )


class WorkerCapabilities(WireModel):
    worker_runtime_version: str | None = None
    capability_install_spec_version: Literal[2] | None = None
    node_pack_install_spec_version: Literal[1] | None = None
    maintenance_actions: list[
        Literal["worker_update", "model_install", "capability_install", "node_pack_install"]
    ] = Field(default_factory=list)
    executors: list[WorkerExecutorCapability] = Field(default_factory=list)


class WorkerView(WireModel):
    id: str
    owner_user_id: str
    manager_broker_id: str | None
    name: str
    signing_public_key: str
    encryption_public_key: str
    certificate: str | None
    executor_type: str
    executor_version: str
    capabilities: WorkerCapabilities
    capacity: int = Field(ge=1, le=64)
    status: Literal["pending", "active", "offline", "draining", "revoked"]
    fencing_counter: int = Field(ge=0)
    last_seen_at: float | None
    capability_auth_enforced_at: float | None
    created_at: float
    updated_at: float
    revoked_at: float | None
    gateway_protocol_features: GatewayProtocolFeatures


class WorkerInviteCreate(WireModel):
    """Owner/admin authorization for a credential-free Worker enrollment."""

    # A Worker key does not exist when the Invite is issued, so an owner
    # certificate cannot be pre-authorized safely.  v0.3 therefore requires a
    # second, explicit decision after the Windows host proves key possession.
    method: Literal["invite_approval"] = "invite_approval"
    pool_id: str
    name: str = Field(default="Windows GPU Worker", min_length=1, max_length=120)
    executor_type: str = Field(default="comfyui", min_length=1, max_length=120)
    executor_version: str = Field(default="1.1.0", max_length=120)
    capacity: int = Field(default=1, ge=1, le=64)
    manager_broker_id: str | None = None
    rate_microtokens_per_second: int = Field(default=0, ge=0, le=1_000_000_000_000)
    ttl_seconds: int = Field(default=1800, ge=60, le=604800)


class WorkerEnrollmentClaim(WireModel):
    version: Literal[1]
    kind: Literal["vgen-worker-enrollment-claim"]
    invite_id: str
    worker_key_id: str = Field(min_length=16, max_length=128)
    name: str = Field(min_length=1, max_length=120)
    signing_public_key: str = Field(min_length=16, max_length=256)
    encryption_public_key: str = Field(min_length=16, max_length=256)
    executor_type: str = Field(min_length=1, max_length=120)
    executor_version: str = Field(default="", max_length=120)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    capacity: int = Field(default=1, ge=1, le=64)


class WorkerEnrollmentClaimRequest(WireModel):
    invite_id: str
    secret: str = Field(
        min_length=16,
        json_schema_extra={"writeOnly": True, "format": "password"},
    )
    claim: WorkerEnrollmentClaim
    proof_signature: str = Field(min_length=16, max_length=256)


class WorkerEnrollmentDecision(WireModel):
    approve: bool
    owner_certificate: str | None = Field(default=None, max_length=16_384)
    allocation_proof: dict[str, Any] | None = None

    @model_validator(mode="after")
    def approval_material_is_complete(self) -> WorkerEnrollmentDecision:
        if self.approve and (not self.owner_certificate or self.allocation_proof is None):
            raise ValueError(
                "approving a Worker requires its owner certificate and allocation proof"
            )
        if not self.approve and (
            self.owner_certificate is not None or self.allocation_proof is not None
        ):
            raise ValueError("rejecting a Worker must not include approval material")
        return self


class WorkerOffer(WireModel):
    pool_id: str


class WorkerLeave(WireModel):
    force: bool = False


class WorkerHeartbeat(WireModel):
    capabilities: dict[str, Any] | None = None


class WorkerWorkflowDeactivate(WireModel):
    workflow_ref: str = Field(
        min_length=1,
        max_length=512,
        pattern=_WORKFLOW_RELEASE_REF_PATTERN,
    )
    workflow_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authorization_source_id: str | None = Field(
        default=None,
        pattern=r"^mtj_[a-z2-7]{26}$",
        description=(
            "Optional maintenance job authorization to revoke during an automatic install "
            "rollback. Omit for an explicit uninstall of every dynamic grant for the release."
        ),
    )


class WorkerManagerSet(WireModel):
    broker_id: str | None


class WorkerUpdateSpec(WireModel):
    kind: Literal["worker_update"]
    target_version: str = Field(
        pattern=(
            r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
            r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
        )
    )
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_size: int = Field(ge=1, le=1024**3)
    apply: Literal["on_idle"] = "on_idle"


class ModelInstallSpec(WireModel):
    kind: Literal["model_install"]
    workflow_ref: str = Field(
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,511}$",
    )
    workflow_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    model_digests: list[str] = Field(min_length=1, max_length=128)

    @field_validator("model_digests")
    @classmethod
    def model_digests_are_unique_and_canonical(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in value
        ):
            raise ValueError("model digests must be unique canonical SHA-256 values")
        # Signing and authorization use one deterministic representation even
        # when a client supplied the same valid set in another order.
        return sorted(value)


class CapabilityInstallSpec(WireModel):
    kind: Literal["capability_install"]
    workflow_ref: str = Field(
        min_length=1,
        max_length=512,
        pattern=_WORKFLOW_RELEASE_REF_PATTERN,
    )
    workflow_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_size: int = Field(ge=1, le=1024**3, strict=True)
    node_classes_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_digests: list[str] | None = Field(default=None, max_length=128)
    node_classes: (
        list[
            Annotated[
                str,
                Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"),
            ]
        ]
        | None
    ) = Field(default=None, max_length=512)
    publisher_key: str | None
    allow_unsigned_workflow: bool = Field(strict=True)
    apply: Literal["on_idle"] = "on_idle"

    @field_validator("publisher_key")
    @classmethod
    def publisher_key_is_canonical_ed25519_base64(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("publisher key must be valid base64") from exc
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("publisher key must be canonical base64 encoding 32 bytes")
        return value

    @model_validator(mode="after")
    def publisher_pin_matches_unsigned_policy(self) -> CapabilityInstallSpec:
        if self.allow_unsigned_workflow:
            if self.publisher_key is not None:
                raise ValueError("unsigned workflows must not include a publisher key")
        elif self.publisher_key is None:
            raise ValueError("signed workflows require a publisher key")
        if (self.model_digests is None) != (self.node_classes is None):
            raise ValueError(
                "model_digests and node_classes must both be omitted or both be present"
            )
        if self.model_digests is not None and (
            self.model_digests != sorted(set(self.model_digests))
            or any(
                re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in self.model_digests
            )
        ):
            raise ValueError("model digests must be sorted unique canonical SHA-256 values")
        if self.node_classes is not None:
            if self.node_classes != sorted(set(self.node_classes)):
                raise ValueError("node classes must be sorted and unique")
            node_digest = hashlib.sha256(
                json.dumps(
                    sorted(self.node_classes),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            if node_digest != self.node_classes_digest:
                raise ValueError("node classes do not match node_classes_digest")
        return self


class NodePackInstallSpec(WireModel):
    kind: Literal["node_pack_install"]
    node_pack_ref: str = Field(
        min_length=1,
        max_length=512,
        pattern=_WORKFLOW_RELEASE_REF_PATTERN,
    )
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_size: int = Field(ge=1, le=1024**3, strict=True)
    node_classes: list[
        Annotated[
            str,
            Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"),
        ]
    ] = Field(min_length=1, max_length=512)
    apply: Literal["on_idle"] = "on_idle"

    @field_validator("node_classes")
    @classmethod
    def node_classes_are_sorted_and_unique(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("Node Pack classes must be sorted and unique")
        return value


WorkerMaintenanceSpec = Annotated[
    WorkerUpdateSpec | ModelInstallSpec | CapabilityInstallSpec | NodePackInstallSpec,
    Field(discriminator="kind"),
]


class MaintenanceIntentPayload(WireModel):
    version: Literal[1]
    kind: Literal["vgen-worker-maintenance-intent"]
    action: Literal[
        "worker_update", "model_install", "capability_install", "node_pack_install"
    ]
    worker_id: str = Field(min_length=1, max_length=120)
    broker_id: str = Field(min_length=1, max_length=120)
    device_id: str = Field(min_length=1, max_length=120)
    spec_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    issued_at: int = Field(ge=1)
    expires_at: int = Field(ge=1)
    nonce: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")

    @model_validator(mode="after")
    def bounded_validity_window(self) -> MaintenanceIntentPayload:
        if self.expires_at <= self.issued_at or self.expires_at - self.issued_at > 604_800:
            raise ValueError("maintenance authorization must expire within seven days")
        return self


class MaintenanceAuthorization(WireModel):
    payload: MaintenanceIntentPayload
    device_certificate: dict[str, Any]
    signature: str = Field(min_length=80, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")

    @field_validator("device_certificate")
    @classmethod
    def device_certificate_is_bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        if (
            set(value) != {"payload", "signature"}
            or len(json.dumps(value, ensure_ascii=True, separators=(",", ":"))) > 16_384
        ):
            raise ValueError("maintenance Device certificate is invalid")
        return value


class WorkerMaintenanceCreate(WireModel):
    spec: WorkerMaintenanceSpec
    authorization: MaintenanceAuthorization

    @model_validator(mode="after")
    def authorization_matches_spec_kind(self) -> WorkerMaintenanceCreate:
        if self.authorization.payload.action != self.spec.kind:
            raise ValueError("maintenance authorization action does not match the specification")
        return self


class WorkerMaintenanceCreateResponse(BaseModel):
    """Request-relative ownership metadata plus the maintenance job view.

    The job view intentionally remains extensible because artifact-backed
    jobs also carry freshly issued upload tickets. The two required fields
    prevent callers from treating a job deduplicated from another signed
    intent as their own rollback or cancellation source.
    """

    model_config = ConfigDict(extra="allow", hide_input_in_errors=True)

    id: str = Field(pattern=r"^mtj_[a-z2-7]{26}$")
    creation_disposition: Literal["created", "deduplicated"] = Field(
        description=(
            "Whether this signed maintenance intent created a new job or joined an "
            "already-active worker-update job. The value is stable across retries of "
            "the same intent."
        )
    )
    intent_owns_job: bool = Field(
        strict=True,
        description=(
            "True only when this signed maintenance intent created the job and may use "
            "its ID for automatic cancellation or source-scoped rollback."
        )
    )


class WorkerMaintenanceCommit(WireModel):
    pass


class WorkerMaintenanceCancel(WireModel):
    pass


class WorkerMaintenanceClaim(WireModel):
    ttl_seconds: int = Field(default=60, ge=15, le=300)
    supported_actions: list[
        Literal["worker_update", "model_install", "capability_install", "node_pack_install"]
    ] = (
        Field(
            default_factory=lambda: ["worker_update", "model_install"],
            min_length=1,
            max_length=4,
        )
    )

    @field_validator("supported_actions")
    @classmethod
    def supported_actions_are_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("maintenance supported actions must be unique")
        return value


class WorkerMaintenanceProgress(WireModel):
    stage: Literal[
        "validating",
        "downloading",
        "verifying",
        "installing",
        "installing_dependencies",
        "staging",
        "activating",
        "pausing_comfyui",
        "probing_nodes",
        "rolling_back",
    ]
    completed_bytes: int = Field(ge=0)
    total_bytes: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def completed_does_not_exceed_total(self) -> WorkerMaintenanceProgress:
        if self.total_bytes is not None and self.completed_bytes > self.total_bytes:
            raise ValueError("completed bytes cannot exceed total bytes")
        return self


class WorkerMaintenanceHeartbeat(WireModel):
    fencing_token: int = Field(ge=1)
    ttl_seconds: int = Field(default=60, ge=15, le=300)
    state: Literal["running", "restarting"]
    progress: WorkerMaintenanceProgress | None = None
    adopt_restart_session: bool = False

    @model_validator(mode="after")
    def session_adoption_is_only_for_restart(self) -> WorkerMaintenanceHeartbeat:
        if self.adopt_restart_session and self.state != "restarting":
            raise ValueError("maintenance session adoption requires restarting state")
        return self


class WorkerUpdateMaintenanceResult(WireModel):
    kind: Literal["worker_update"]
    status: Literal["activated", "rolled_back", "failed"]
    target_version: str = Field(
        pattern=(
            r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
            r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
        )
    )
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    error_code: int | None = Field(default=None, ge=100000, le=999999)


class ModelInstallMaintenanceResult(WireModel):
    kind: Literal["model_install"]
    status: Literal["installed", "already_installed", "failed"]
    installed_model_digests: list[str] = Field(default_factory=list, max_length=128)
    failed_model_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    error_code: int | None = Field(default=None, ge=100000, le=999999)

    @field_validator("installed_model_digests")
    @classmethod
    def installed_digests_are_unique_and_canonical(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in value
        ):
            raise ValueError("installed model digests must be unique canonical SHA-256 values")
        return value


class CapabilityInstallMaintenanceResult(WireModel):
    kind: Literal["capability_install"]
    status: Literal["activated", "already_active", "repaired", "failed"]
    workflow_ref: str = Field(
        min_length=1,
        max_length=512,
        pattern=_WORKFLOW_RELEASE_REF_PATTERN,
    )
    workflow_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ready: bool | None = Field(default=None, strict=True)
    error_code: int | None = Field(default=None, ge=100000, le=999999, strict=True)

    @model_validator(mode="before")
    @classmethod
    def status_selects_an_exact_field_set(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        common = {
            "kind",
            "status",
            "workflow_ref",
            "workflow_digest",
            "artifact_sha256",
        }
        expected = common | ({"error_code"} if value.get("status") == "failed" else {"ready"})
        if set(value) != expected:
            raise ValueError("capability install result fields do not match its status")
        return value

    @model_validator(mode="after")
    def success_and_failure_fields_are_disjoint(
        self,
    ) -> CapabilityInstallMaintenanceResult:
        if self.status == "failed":
            if self.ready is not None or self.error_code is None:
                raise ValueError("failed capability installs require only an error code")
        elif self.ready is None or self.error_code is not None:
            raise ValueError("successful capability installs require readiness without an error")
        return self


class NodePackInstallMaintenanceResult(WireModel):
    kind: Literal["node_pack_install"]
    status: Literal["installed", "already_installed", "failed"]
    node_pack_ref: str = Field(
        min_length=1,
        max_length=512,
        pattern=_WORKFLOW_RELEASE_REF_PATTERN,
    )
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    loaded: bool | None = Field(default=None, strict=True)
    error_code: int | None = Field(default=None, ge=100000, le=999999, strict=True)
    reason_code: str | None = Field(
        default=None,
        pattern=r"^NODE_PACK_[A-Z0-9_]{1,96}$",
    )

    @model_validator(mode="after")
    def success_and_failure_fields_are_disjoint(
        self,
    ) -> NodePackInstallMaintenanceResult:
        if self.status == "failed":
            if (
                self.loaded is not None
                or self.error_code is None
                or self.reason_code is None
            ):
                raise ValueError(
                    "failed Node Pack installs require an error and fixed reason code"
                )
        elif (
            self.loaded is not True
            or self.error_code is not None
            or self.reason_code is not None
        ):
            raise ValueError("successful Node Pack installs require loaded=true")
        return self


WorkerMaintenanceResult = Annotated[
    WorkerUpdateMaintenanceResult
    | ModelInstallMaintenanceResult
    | CapabilityInstallMaintenanceResult
    | NodePackInstallMaintenanceResult,
    Field(discriminator="kind"),
]


class WorkerMaintenanceComplete(WireModel):
    fencing_token: int = Field(ge=1)
    succeeded: bool
    result: WorkerMaintenanceResult


class AllocationApproval(WireModel):
    proof: dict[str, Any]


class RateProposal(WireModel):
    workspace_id: str
    # Reserved for the future duration-based pricing formula. It is snapshotted
    # today but no charge is calculated until that formula is introduced.
    rate_microtokens_per_second: int = Field(ge=0, le=1_000_000_000_000)


class UsageReversalReason(StrEnum):
    DUPLICATE_CHARGE = "duplicate_charge"
    RATE_CORRECTION = "rate_correction"
    PROVIDER_FAULT = "provider_fault"
    PLATFORM_FAULT = "platform_fault"
    CONSUMER_REFUND = "consumer_refund"


class UsageReversalCreate(WireModel):
    reason_code: UsageReversalReason


class ArtifactPrepare(WireModel):
    kind: str = Field(min_length=1, max_length=120)
    encrypted_size: int = Field(ge=1, le=100 * 1024**3)
    media_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("media_metadata")
    @classmethod
    def media_metadata_is_plaintext_safe(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            return validate_artifact_media_metadata(value)
        except PublicMetadataError as exc:
            raise ValueError(exc.reason) from exc


class TaskPrepare(WireModel):
    workspace_id: str
    pool_id: str
    workflow_ref: str = Field(min_length=1, max_length=512)
    workflow_digest: str = Field(min_length=16, max_length=256)
    executor_type: str = Field(min_length=1, max_length=120)
    public_requirements: dict[str, Any] = Field(default_factory=dict)
    input_artifacts: list[ArtifactPrepare] = Field(default_factory=list, max_length=32)
    client_channel: Literal["api", "cli", "broker"] = "api"
    priority: int = Field(default=0, ge=-1000, le=1000)
    reservation_ttl_seconds: int = Field(default=120, ge=15, le=900)

    @field_validator("public_requirements")
    @classmethod
    def public_requirements_are_plaintext_safe(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            return validate_public_requirements(value)
        except PublicMetadataError as exc:
            raise ValueError(exc.reason) from exc


class TaskPreflight(WireModel):
    """Public scheduling facts used for a non-reserving readiness check."""

    workspace_id: str
    pool_id: str
    workflow_ref: str = Field(min_length=1, max_length=512)
    workflow_digest: str = Field(min_length=16, max_length=256)
    executor_type: str = Field(min_length=1, max_length=120)
    public_requirements: dict[str, Any] = Field(default_factory=dict)

    @field_validator("public_requirements")
    @classmethod
    def public_requirements_are_plaintext_safe(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            return validate_public_requirements(value)
        except PublicMetadataError as exc:
            raise ValueError(exc.reason) from exc


class TaskPreflightResult(WireModel):
    ready: bool
    state: Literal[
        "no_allocated_worker",
        "worker_offline_or_busy",
        "queue_available",
        "queue_full",
        "capability_mismatch",
        "rate_not_approved",
        "ready",
    ]
    reason: str
    workspace_id: str
    pool_id: str
    executor_type: str


class ArtifactCommit(WireModel):
    kind: str = Field(min_length=1, max_length=120)
    store_type: Literal["local", "oss", "s3"]
    object_ref: str = Field(min_length=1, max_length=2048)
    content_digest: str | None = Field(default=None, max_length=256)
    encrypted_size: int | None = Field(default=None, ge=0)
    media_metadata: dict[str, Any] = Field(default_factory=dict)


class ArtifactUploadReceipt(WireModel):
    artifact_id: str = Field(min_length=1, max_length=120)
    encrypted_size: int = Field(ge=0)
    content_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class TaskCommit(WireModel):
    encrypted_payload: str = Field(min_length=1)
    worker_tdk_envelope: str = Field(min_length=1)
    reader_envelope: str = Field(min_length=1)
    key_algorithm: str = Field(min_length=1, max_length=120)
    artifacts: list[ArtifactCommit] = Field(default_factory=list, max_length=32)
    artifact_receipts: list[ArtifactUploadReceipt] = Field(default_factory=list, max_length=32)


class TaskRekey(WireModel):
    replacement_worker_id: str
    worker_tdk_envelope: str = Field(min_length=1)
    key_algorithm: str = Field(min_length=1, max_length=120)


class LeaseRequest(WireModel):
    ttl_seconds: int = Field(default=60, ge=15, le=300)


class AttemptHeartbeat(WireModel):
    fencing_token: int = Field(ge=1)
    started: bool = False
    ttl_seconds: int = Field(default=60, ge=15, le=300)
    progress: dict[str, Any] | None = None


class OutputArtifact(WireModel):
    # Every output object is reserved by the Gateway before execution.  A
    # Worker may complete only that opaque object; arbitrary store references
    # are never accepted as a substitute for a capability-bound reservation.
    artifact_id: str = Field(min_length=1, max_length=120)
    kind: str = Field(min_length=1, max_length=120)
    store_type: Literal["local", "oss", "s3"] | None = None
    object_ref: str | None = Field(default=None, min_length=1, max_length=2048)
    content_digest: str | None = Field(default=None, max_length=256)
    encrypted_size: int | None = Field(default=None, ge=0)
    media_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("media_metadata")
    @classmethod
    def media_metadata_is_plaintext_safe(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            return validate_reported_artifact_media_metadata(value)
        except PublicMetadataError as exc:
            raise ValueError(exc.reason) from exc


class AttemptFinish(WireModel):
    fencing_token: int = Field(ge=1)
    succeeded: bool
    output_artifacts: list[OutputArtifact] = Field(default_factory=list, max_length=32)
    metrics: dict[str, Any] = Field(default_factory=dict)
    worker_signature: str | None = None
    failure_code: int | None = None
    responsibility: Literal["consumer", "provider", "platform", "none"] = "none"
    safe_failure_details: dict[str, Any] = Field(default_factory=dict)
