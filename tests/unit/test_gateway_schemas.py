from __future__ import annotations

import sqlite3

import pytest
from pydantic import ValidationError

from vgen.gateway.database import GatewayDatabase
from vgen.gateway.schemas import (
    ArtifactPrepare,
    OutputArtifact,
    RateProposal,
    TaskPreflight,
    TaskPrepare,
)


def test_existing_gateway_adds_broker_runtime_columns(tmp_path) -> None:
    path = tmp_path / "gateway.db"
    connection = sqlite3.connect(path)
    connection.execute(
        """CREATE TABLE broker_devices (
           id TEXT PRIMARY KEY,
           broker_id TEXT NOT NULL,
           device_id TEXT NOT NULL,
           status TEXT NOT NULL,
           approved_by_user_id TEXT NOT NULL,
           created_at REAL NOT NULL,
           revoked_at REAL,
           UNIQUE(broker_id, device_id))"""
    )
    connection.commit()
    connection.close()

    database = GatewayDatabase(str(path))
    try:
        columns = {
            row["name"] for row in database.fetchall("PRAGMA table_info(broker_devices)")
        }
    finally:
        database.close()

    assert {
        "runtime_version",
        "protocol_version",
        "build_commit",
        "journal_pending",
        "heartbeat_at",
    } <= columns


def test_rate_proposal_is_bounded_to_sqlite_integer_range() -> None:
    maximum = 1_000_000_000_000
    value = RateProposal(
        workspace_id="wsp_test",
        rate_microtokens_per_second=maximum,
    )
    assert value.rate_microtokens_per_second == maximum

    with pytest.raises(ValidationError):
        RateProposal(
            workspace_id="wsp_test",
            rate_microtokens_per_second=maximum + 1,
        )


def test_task_public_requirements_are_closed_and_canonical() -> None:
    minimal = TaskPrepare(
        workspace_id="wsp_test",
        pool_id="pol_test",
        workflow_ref="vgen/test@1.0.0",
        workflow_digest="sha256:" + "a" * 64,
        executor_type="comfyui",
        public_requirements={
            "operation": "t2v",
            "payload_format": "comfyui-api-graph/v1",
            "model_digests": [],
        },
    )
    assert "executor_min_version" not in minimal.public_requirements
    assert "runtime_min_version" not in minimal.public_requirements
    assert "min_vram_bytes" not in minimal.public_requirements
    assert "min_ram_bytes" not in minimal.public_requirements

    value = TaskPrepare(
        workspace_id="wsp_test",
        pool_id="pol_test",
        workflow_ref="vgen/test@1.0.0",
        workflow_digest="sha256:" + "a" * 64,
        executor_type="comfyui",
        public_requirements={
            "operation": "flf",
            "payload_format": "comfyui-api-graph/v1",
            "executor_min_version": "1.2.3",
            "runtime_min_version": "0.30.0",
            "model_digests": ["A" * 64],
            "min_vram_bytes": 16_000_000_000,
            "min_ram_bytes": 32_000_000_000,
            "output_count": 1,
        },
    )
    assert value.public_requirements["model_digests"] == ["sha256:" + "a" * 64]

    with pytest.raises(ValidationError) as raised:
        TaskPrepare(
            workspace_id="wsp_test",
            pool_id="pol_test",
            workflow_ref="vgen/test@1.0.0",
            workflow_digest="sha256:" + "a" * 64,
            executor_type="comfyui",
            public_requirements={"prompt": "PRIVATE_PROMPT_must_not_reach_gateway"},
        )
    assert "PRIVATE_PROMPT" not in str(raised.value)

    preflight = TaskPreflight(
        workspace_id="wsp_test",
        pool_id="pol_test",
        workflow_ref="vgen/test@1.0.0",
        workflow_digest="sha256:" + "b" * 64,
        executor_type="comfyui",
        public_requirements={"model_digests": ["A" * 64]},
    )
    assert preflight.public_requirements == {"model_digests": ["sha256:" + "a" * 64]}


def test_artifact_media_metadata_rejects_free_form_plaintext() -> None:
    prepared = ArtifactPrepare(
        kind="image",
        encrypted_size=123,
        media_metadata={"filename": "first-frame.png", "media_type": "image/png"},
    )
    assert prepared.media_metadata == {
        "filename": "first-frame.png",
        "media_type": "image/png",
    }
    output = OutputArtifact(
        artifact_id="art_test",
        kind="video",
        media_metadata={"filename": "result.mp4", "frames": 81, "duration_ms": 5000},
    )
    assert output.media_metadata["frames"] == 81

    with pytest.raises(ValidationError) as raised:
        OutputArtifact(
            artifact_id="art_test",
            kind="video",
            media_metadata={"prompt": "PRIVATE_PROMPT_must_not_reach_gateway"},
        )
    assert "PRIVATE_PROMPT" not in str(raised.value)
