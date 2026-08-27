from __future__ import annotations

import base64
import sqlite3

import pytest
from pydantic import ValidationError

from vgen.gateway.database import SCHEMA, GatewayDatabase
from vgen.gateway.schemas import (
    ArtifactPrepare,
    CapabilityInstallMaintenanceResult,
    CapabilityInstallSpec,
    NodePackInstallMaintenanceResult,
    OutputArtifact,
    RateProposal,
    TaskPreflight,
    TaskPrepare,
    WorkerMaintenanceProgress,
)


def _capability_spec(**overrides):
    value = {
        "kind": "capability_install",
        "workflow_ref": "vgen/ltx-2.5@1.0.0",
        "workflow_digest": "sha256:" + "a" * 64,
        "artifact_sha256": "b" * 64,
        "artifact_size": 123,
        "node_classes_digest": "c" * 64,
        "publisher_key": base64.b64encode(b"p" * 32).decode("ascii"),
        "allow_unsigned_workflow": False,
        "apply": "on_idle",
    }
    value.update(overrides)
    return value


def test_capability_install_schema_enforces_signed_or_explicitly_unsigned() -> None:
    signed = CapabilityInstallSpec(**_capability_spec())
    assert signed.publisher_key is not None

    unsigned = CapabilityInstallSpec(
        **_capability_spec(publisher_key=None, allow_unsigned_workflow=True)
    )
    assert unsigned.publisher_key is None

    for invalid in (
        _capability_spec(publisher_key=None),
        _capability_spec(allow_unsigned_workflow=True),
        _capability_spec(publisher_key=base64.b64encode(b"short").decode("ascii")),
        _capability_spec(node_classes_digest="sha256:" + "c" * 64),
        _capability_spec(workflow_ref="VGen/LTX@1.0.0"),
        _capability_spec(allow_unsigned_workflow="false"),
    ):
        with pytest.raises(ValidationError):
            CapabilityInstallSpec(**invalid)


def test_capability_install_result_allows_not_ready_but_separates_failure_fields() -> None:
    identifiers = {
        "kind": "capability_install",
        "workflow_ref": "vgen/ltx-2.5@1.0.0",
        "workflow_digest": "sha256:" + "a" * 64,
        "artifact_sha256": "b" * 64,
    }
    result = CapabilityInstallMaintenanceResult(**identifiers, status="activated", ready=False)
    assert result.ready is False
    repaired = CapabilityInstallMaintenanceResult(**identifiers, status="repaired", ready=True)
    assert repaired.ready is True
    CapabilityInstallMaintenanceResult(**identifiers, status="failed", error_code=330006)

    with pytest.raises(ValidationError):
        CapabilityInstallMaintenanceResult(**identifiers, status="activated")
    with pytest.raises(ValidationError):
        CapabilityInstallMaintenanceResult(
            **identifiers, status="failed", ready=False, error_code=330006
        )
    with pytest.raises(ValidationError):
        CapabilityInstallMaintenanceResult(
            **identifiers, status="activated", ready=False, error_code=None
        )


def test_node_pack_failure_exposes_only_a_fixed_machine_reason() -> None:
    identifiers = {
        "kind": "node_pack_install",
        "node_pack_ref": "vgen/comfyui-gguf@1.0.1",
        "artifact_sha256": "a" * 64,
    }
    failed = NodePackInstallMaintenanceResult(
        **identifiers,
        status="failed",
        error_code=340004,
        reason_code="NODE_PACK_TARGET_UNSAFE",
    )
    assert failed.reason_code == "NODE_PACK_TARGET_UNSAFE"

    with pytest.raises(ValidationError):
        NodePackInstallMaintenanceResult(
            **identifiers,
            status="failed",
            error_code=340004,
        )
    with pytest.raises(ValidationError):
        NodePackInstallMaintenanceResult(
            **identifiers,
            status="failed",
            error_code=340004,
            reason_code="C:\\Users\\private",
        )


@pytest.mark.parametrize(
    "stage",
    [
        "installing_dependencies",
        "pausing_comfyui",
        "probing_nodes",
        "rolling_back",
    ],
)
def test_node_pack_maintenance_progress_accepts_reviewed_stages(stage: str) -> None:
    progress = WorkerMaintenanceProgress(
        stage=stage,
        completed_bytes=123,
        total_bytes=123,
    )
    assert progress.stage == stage


def test_v1_maintenance_tables_rebuild_to_v3_without_losing_rows(tmp_path) -> None:
    path = tmp_path / "legacy-maintenance-v1.db"
    legacy_schema = SCHEMA.replace(
        "CHECK(kind IN (\n        'worker_update','model_install','capability_install','node_pack_install'\n    ))",
        "CHECK(kind IN ('worker_update','model_install'))",
    ).replace(
        "CHECK(kind IN (\n        'worker_update','capability_install','node_pack_install'\n    ))",
        "CHECK(kind='worker_update')",
    )
    legacy = sqlite3.connect(path)
    legacy.executescript(legacy_schema)
    legacy.executescript(
        """
        INSERT INTO schema_meta(version) VALUES (1);
        INSERT INTO users
            (id,display_name,root_signing_public_key,root_encryption_public_key,status,
             is_operator,created_at,updated_at)
            VALUES ('usr_owner','Owner','root-sign','root-encrypt','active',0,1,1);
        INSERT INTO devices
            (id,user_id,name,signing_public_key,encryption_public_key,status,created_at)
            VALUES ('dev_owner','usr_owner','Device','device-sign','device-encrypt','active',1);
        INSERT INTO brokers
            (id,owner_user_id,name,status,created_at,updated_at)
            VALUES ('brk_home','usr_owner','Home','active',1,1);
        INSERT INTO workers
            (id,owner_user_id,manager_broker_id,name,signing_public_key,
             encryption_public_key,executor_type,status,created_at,updated_at)
            VALUES ('wrk_gpu','usr_owner','brk_home','GPU','worker-sign','worker-encrypt',
                    'comfyui','active',1,1);
        INSERT INTO worker_maintenance_jobs
            (id,worker_id,broker_id,issued_by_user_id,issued_by_device_id,kind,spec,
             spec_digest,authorization,dedupe_key,state,expires_at,created_at,updated_at)
            VALUES ('mtj_existing','wrk_gpu','brk_home','usr_owner','dev_owner',
                    'worker_update','{}','sha256:old','{}','dedupe-old','awaiting_upload',
                    100,1,1);
        INSERT INTO maintenance_artifacts
            (id,job_id,kind,store_type,object_ref,expected_size,expected_sha256,state,
             created_at,updated_at)
            VALUES ('art_existing','mtj_existing','worker_update','local','art_existing',
                    10,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'uploaded',1,1);
        """
    )
    legacy.commit()
    legacy.close()

    database = GatewayDatabase(str(path))
    try:
        assert database.fetchone("SELECT version FROM schema_meta")["version"] == 3
        assert (
            database.fetchone(
                "SELECT kind,state FROM worker_maintenance_jobs WHERE id='mtj_existing'"
            )["kind"]
            == "worker_update"
        )
        assert (
            database.fetchone("SELECT state FROM maintenance_artifacts WHERE id='art_existing'")[
                "state"
            ]
            == "uploaded"
        )
        assert database.fetchall("PRAGMA foreign_key_check") == []
        database.execute(
            """INSERT INTO worker_maintenance_jobs
               (id,worker_id,broker_id,issued_by_user_id,issued_by_device_id,kind,spec,
                spec_digest,authorization,dedupe_key,state,expires_at,created_at,updated_at)
               VALUES ('mtj_node_pack','wrk_gpu','brk_home','usr_owner','dev_owner',
                       'node_pack_install','{}','sha256:pack','{}','dedupe-pack',
                       'awaiting_upload',100,3,3)"""
        )
        database.execute(
            """INSERT INTO maintenance_artifacts
               (id,job_id,kind,store_type,object_ref,expected_size,expected_sha256,state,
                created_at,updated_at)
               VALUES ('art_node_pack','mtj_node_pack','node_pack_install','local',
                       'art_node_pack',10,?,'pending',3,3)""",
            ("d" * 64,),
        )
        assert database.fetchone("PRAGMA foreign_keys")[0] == 1

        database.execute(
            """INSERT INTO worker_maintenance_jobs
               (id,worker_id,broker_id,issued_by_user_id,issued_by_device_id,kind,spec,
                spec_digest,authorization,dedupe_key,state,expires_at,created_at,updated_at)
               VALUES ('mtj_capability','wrk_gpu','brk_home','usr_owner','dev_owner',
                       'capability_install','{}','sha256:new','{}','dedupe-new',
                       'awaiting_upload',100,2,2)"""
        )
        database.execute(
            """INSERT INTO maintenance_artifacts
               (id,job_id,kind,store_type,object_ref,expected_size,expected_sha256,state,
                created_at,updated_at)
               VALUES ('art_capability','mtj_capability','capability_install','local',
                       'art_capability',10,?,'pending',2,2)""",
            ("b" * 64,),
        )
        database.execute(
            """INSERT INTO maintenance_intent_receipts
               (device_id,nonce,authorization_digest,job_id,expires_at,created_at)
               VALUES ('dev_owner','post-migration-nonce',?,'mtj_capability',100,2)""",
            ("c" * 64,),
        )
        receipt_foreign_keys = {
            row["from"]: row["table"]
            for row in database.fetchall("PRAGMA foreign_key_list(maintenance_intent_receipts)")
        }
        assert receipt_foreign_keys["job_id"] == "worker_maintenance_jobs"
        assert database.fetchall("PRAGMA foreign_key_check") == []
    finally:
        database.close()


def test_v2_capability_authorizations_migrate_to_independent_sources(tmp_path) -> None:
    path = tmp_path / "legacy-capability-auth-v2.db"
    initialized = GatewayDatabase(str(path))
    initialized.close()

    legacy = sqlite3.connect(path)
    legacy.executescript(
        """
        PRAGMA foreign_keys=OFF;
        DROP TABLE worker_workflow_authorizations;
        DROP TABLE worker_model_authorizations;
        CREATE TABLE worker_workflow_authorizations (
            worker_id TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
            workflow_ref TEXT NOT NULL,
            workflow_digest TEXT NOT NULL,
            spec_digest TEXT NOT NULL,
            maintenance_job_id TEXT NOT NULL,
            node_classes TEXT NOT NULL DEFAULT '[]',
            authorized_at REAL NOT NULL,
            revoked_at REAL,
            PRIMARY KEY(worker_id, workflow_ref, workflow_digest, spec_digest)
        );
        CREATE TABLE worker_model_authorizations (
            worker_id TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
            workflow_ref TEXT NOT NULL,
            workflow_digest TEXT NOT NULL,
            model_digest TEXT NOT NULL,
            spec_digest TEXT NOT NULL,
            maintenance_job_id TEXT NOT NULL,
            authorized_at REAL NOT NULL,
            revoked_at REAL,
            PRIMARY KEY(worker_id, workflow_ref, workflow_digest, model_digest, spec_digest)
        );
        UPDATE schema_meta SET version=2;
        INSERT INTO users
            (id,display_name,root_signing_public_key,root_encryption_public_key,status,
             is_operator,created_at,updated_at)
            VALUES ('usr_owner','Owner','root-sign','root-encrypt','active',0,1,1);
        INSERT INTO workers
            (id,owner_user_id,name,signing_public_key,encryption_public_key,
             executor_type,executor_version,capabilities,capacity,status,created_at,updated_at)
            VALUES ('wrk_gpu','usr_owner','GPU','worker-sign','worker-encrypt',
                    'comfyui','1.0.0','{}',1,'offline',1,1);
        INSERT INTO worker_workflow_authorizations
            (worker_id,workflow_ref,workflow_digest,spec_digest,maintenance_job_id,
             node_classes,authorized_at)
            VALUES ('wrk_gpu','vgen/test@1.0.0','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'mtj_first','[]',1);
        INSERT INTO worker_model_authorizations
            (worker_id,workflow_ref,workflow_digest,model_digest,spec_digest,
             maintenance_job_id,authorized_at)
            VALUES ('wrk_gpu','vgen/test@1.0.0','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'mtj_first',1);
        """
    )
    legacy.commit()
    legacy.close()

    database = GatewayDatabase(str(path))
    try:
        assert database.fetchone("SELECT version FROM schema_meta")["version"] == 3
        workflow_columns = {
            row["name"]
            for row in database.fetchall("PRAGMA table_info(worker_workflow_authorizations)")
        }
        assert "authorization_source_id" in workflow_columns
        assert "maintenance_job_id" not in workflow_columns
        assert (
            database.fetchone("SELECT authorization_source_id FROM worker_workflow_authorizations")[
                "authorization_source_id"
            ]
            == "mtj_first"
        )

        workflow_digest = "sha256:" + "a" * 64
        spec_digest = "sha256:" + "b" * 64
        model_digest = "sha256:" + "c" * 64
        database.execute(
            """INSERT INTO worker_workflow_authorizations
               (worker_id,authorization_source_id,workflow_ref,workflow_digest,
                spec_digest,node_classes,authorized_at)
               VALUES ('wrk_gpu','mtj_second','vgen/test@1.0.0',?,?,'[]',2)""",
            (workflow_digest, spec_digest),
        )
        database.execute(
            """INSERT INTO worker_model_authorizations
               (worker_id,authorization_source_id,workflow_ref,workflow_digest,
                model_digest,spec_digest,authorized_at)
               VALUES ('wrk_gpu','mtj_second','vgen/test@1.0.0',?,?,?,2)""",
            (workflow_digest, model_digest, spec_digest),
        )
        assert (
            database.fetchone("SELECT COUNT(*) AS n FROM worker_workflow_authorizations")["n"] == 2
        )
        assert database.fetchone("SELECT COUNT(*) AS n FROM worker_model_authorizations")["n"] == 2
        assert database.fetchall("PRAGMA foreign_key_check") == []
    finally:
        database.close()


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
        columns = {row["name"] for row in database.fetchall("PRAGMA table_info(broker_devices)")}
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
