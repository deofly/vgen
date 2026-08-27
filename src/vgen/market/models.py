from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .paths import canonical_package_path, package_path_key

WORKFLOW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$")
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
RESERVED_WORKFLOW_ROOT_FILES = frozenset({"artifact.sig", "checksums.sha256", "workflow.lock"})


def validate_workflow_id(value: str) -> str:
    if not WORKFLOW_ID_RE.fullmatch(value):
        raise ValueError("workflow id must be namespace/name using lowercase characters")
    namespace, name = value.split("/", 1)
    try:
        canonical_package_path(namespace, label="workflow namespace")
        canonical_package_path(name, label="workflow name")
    except ValueError as exc:
        raise ValueError(
            "workflow id components must be portable across supported filesystems"
        ) from exc
    return value


def validate_workflow_version(value: str) -> str:
    try:
        canonical_package_path(value, label="workflow version")
    except ValueError as exc:
        raise ValueError("workflow version must be a portable SemVer") from exc
    without_build, _, build = value.partition("+")
    _core, separator, prerelease = without_build.partition("-")
    if (
        not SEMVER_RE.fullmatch(value)
        or (separator and any(not item for item in prerelease.split(".")))
        or (build and any(not item for item in build.split(".")))
    ):
        raise ValueError("workflow version must be SemVer")
    return value


def _package_relative_path(value: str, *, label: str) -> str:
    """Normalize a package path without accepting another platform's escapes."""

    return canonical_package_path(value, label=label, allow_backslash=True)


class ModelRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    folder: str
    source: str | None = None
    revision: str | None = None
    sha256: str
    size: int = Field(ge=0)
    # Informational provenance only. Installation and scheduling are bound to
    # immutable bytes, not to a client-side interpretation of license text.
    license: str | None = None
    gated: bool = False
    manual_download: bool = False

    @field_validator("filename", "folder")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        return _package_relative_path(value, label="model path")

    @field_validator("sha256")
    @classmethod
    def valid_sha256(cls, value: str) -> str:
        normalized = value.removeprefix("sha256:").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise ValueError("model sha256 must contain exactly 64 hexadecimal characters")
        return normalized

    @field_validator("source")
    @classmethod
    def secure_source(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("https://"):
            raise ValueError("model source must use HTTPS")
        return value

    @field_validator("revision", "license")
    @classmethod
    def nonempty_metadata(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("model revision and license must be non-empty")
        return value


class CustomNodeRequirement(BaseModel):
    """Pinned executable dependency, optionally fulfilled by a reviewed Node Pack."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    source: str
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    license: str | None = Field(default=None, min_length=1, max_length=120)
    node_types: list[str] = Field(min_length=1, max_length=128)
    node_pack: str | None = None
    node_pack_source: str | None = None
    node_pack_sha256: str | None = None
    manual_install: bool = True

    @field_validator("source")
    @classmethod
    def secure_source(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("custom node source must use HTTPS")
        return value

    @field_validator("node_types")
    @classmethod
    def unique_node_types(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > 160 for item in value):
            raise ValueError("custom node types must be non-empty and bounded")
        if len(value) != len(set(value)):
            raise ValueError("custom node types must be unique")
        return value

    @field_validator("node_pack")
    @classmethod
    def valid_node_pack_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        node_pack_id, separator, version = value.partition("@")
        if not separator or "@" in version:
            raise ValueError("Node Pack reference must be id@version")
        validate_workflow_id(node_pack_id)
        validate_workflow_version(version)
        return value

    @field_validator("node_pack_sha256")
    @classmethod
    def valid_node_pack_digest(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.removeprefix("sha256:").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise ValueError("Node Pack sha256 must contain exactly 64 hexadecimal characters")
        return normalized

    @field_validator("node_pack_source")
    @classmethod
    def secure_node_pack_source(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("https://"):
            raise ValueError("Node Pack artifact source must use HTTPS")
        return value

    @model_validator(mode="after")
    def coherent_install_source(self) -> CustomNodeRequirement:
        managed = any(
            item is not None
            for item in (self.node_pack, self.node_pack_source, self.node_pack_sha256)
        )
        if managed != (
            self.node_pack is not None
            and self.node_pack_source is not None
            and self.node_pack_sha256 is not None
        ):
            raise ValueError(
                "managed custom nodes require a Node Pack reference, source, and digest"
            )
        if managed == self.manual_install:
            raise ValueError("custom node must use exactly one manual or managed install source")
        return self


class WorkflowVariant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    executor_type: str
    payload_format: str
    payload: str
    mapping: str | None = None
    operations: list[Literal["t2v", "i2v", "flf", "t2i", "i2i"]]
    models: list[ModelRequirement] = Field(default_factory=list)
    custom_nodes: list[CustomNodeRequirement] = Field(default_factory=list, max_length=8)
    executor_min_version: str | None = None
    runtime_min_version: str | None = None
    min_vram_bytes: int | None = Field(default=None, ge=0)
    min_ram_bytes: int | None = Field(default=None, ge=0)

    @field_validator("payload", "mapping")
    @classmethod
    def package_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = _package_relative_path(value, label="workflow file")
        if package_path_key(normalized) in RESERVED_WORKFLOW_ROOT_FILES:
            raise ValueError("workflow payload cannot use a reserved package metadata file")
        return normalized

    @field_validator("executor_min_version", "runtime_min_version")
    @classmethod
    def valid_executor_version(cls, value: str | None) -> str | None:
        if value is not None and not SEMVER_RE.fullmatch(value):
            raise ValueError("executor/runtime minimum version must be SemVer")
        return value

    @model_validator(mode="after")
    def unambiguous_model_placements(self) -> WorkflowVariant:
        placements: set[str] = set()
        graph_names: set[str] = set()
        digest_sizes: dict[str, int] = {}
        for model in self.models:
            placement = package_path_key(f"{model.folder}/{model.filename}")
            if placement in placements:
                raise ValueError("model placements must be unique across supported platforms")
            placements.add(placement)

            # ComfyUI graphs expose loader filenames, while `folder` selects the
            # model category. Reusing one normalized filename across categories
            # makes set-based graph authorization ambiguous and is therefore
            # rejected until loader-specific bindings become part of the schema.
            graph_name = package_path_key(model.filename)
            if graph_name in graph_names:
                raise ValueError("model filenames must be unique within a workflow variant")
            graph_names.add(graph_name)

            previous_size = digest_sizes.get(model.sha256)
            if previous_size is not None and previous_size != model.size:
                raise ValueError("shared model digests must use one byte size")
            digest_sizes[model.sha256] = model.size
        return self


class Publisher(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    public_key: str | None = None
    homepage: str | None = None


class WorkflowManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    id: str
    version: str
    title: str
    summary: str
    license: str | None = None
    provenance: Literal["market", "custom"]
    publisher: Publisher
    homepage: str | None = None
    source: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    variants: list[WorkflowVariant]

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        return validate_workflow_id(value)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        return validate_workflow_version(value)

    @field_validator("variants")
    @classmethod
    def unique_variants(cls, value: list[WorkflowVariant]) -> list[WorkflowVariant]:
        if not value:
            raise ValueError("at least one executor variant is required")
        names = [variant.name for variant in value]
        if len(names) != len(set(names)):
            raise ValueError("variant names must be unique")
        return value

    @model_validator(mode="after")
    def complete_market_dependencies(self) -> WorkflowManifest:
        if self.provenance != "market":
            return self
        for variant in self.variants:
            for model in variant.models:
                if model.source is None or model.revision is None:
                    raise ValueError(
                        "market model requirements need an HTTPS source and immutable revision"
                    )
        return self

    @classmethod
    def load(cls, path: Path) -> WorkflowManifest:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ValueError(f"manifest is unavailable or invalid: {path}") from exc
        if not isinstance(raw, dict):
            raise ValueError("manifest must contain a YAML object")
        return cls.model_validate(raw)
