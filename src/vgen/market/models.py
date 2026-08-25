from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

WORKFLOW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$")
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


def _package_relative_path(value: str, *, label: str) -> str:
    """Normalize a package path without accepting another platform's escapes."""

    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized.strip()
        or "\x00" in normalized
        or "://" in normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} must be a non-empty relative package path")
    return path.as_posix()


class ModelRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    folder: str
    source: str | None = None
    revision: str | None = None
    sha256: str
    size: int = Field(ge=0)
    license: str
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
    """Pinned executable dependency which VGen never installs automatically."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    source: str
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    license: str = Field(min_length=1, max_length=120)
    node_types: list[str] = Field(min_length=1, max_length=128)
    manual_install: Literal[True] = True

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


class WorkflowVariant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    executor_type: str
    payload_format: str
    payload: str
    mapping: str | None = None
    operations: list[Literal["t2v", "i2v", "flf", "t2i", "i2i"]]
    models: list[ModelRequirement] = Field(default_factory=list)
    custom_nodes: list[CustomNodeRequirement] = Field(default_factory=list)
    executor_min_version: str | None = None
    runtime_min_version: str | None = None
    min_vram_bytes: int | None = Field(default=None, ge=0)
    min_ram_bytes: int | None = Field(default=None, ge=0)

    @field_validator("payload", "mapping")
    @classmethod
    def package_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _package_relative_path(value, label="workflow file")

    @field_validator("executor_min_version", "runtime_min_version")
    @classmethod
    def valid_executor_version(cls, value: str | None) -> str | None:
        if value is not None and not SEMVER_RE.fullmatch(value):
            raise ValueError("executor/runtime minimum version must be SemVer")
        return value


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
    license: str
    provenance: Literal["market", "custom"]
    publisher: Publisher
    homepage: str | None = None
    source: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    variants: list[WorkflowVariant]

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        if not WORKFLOW_ID_RE.fullmatch(value):
            raise ValueError("workflow id must be namespace/name using lowercase characters")
        return value

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        if not SEMVER_RE.fullmatch(value):
            raise ValueError("workflow version must be SemVer")
        return value

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
