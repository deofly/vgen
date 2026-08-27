from pathlib import Path

import vgen.gateway.repository as repository_module
from vgen.gateway.bootstrap_capabilities import (
    COMFYUI_BOOTSTRAP_WORKFLOWS,
    BootstrapWorkflowAuthorization,
)
from vgen.gateway.database import GatewayDatabase, now
from vgen.gateway.repository import GatewayRepository
from vgen.market.capabilities import comfyui_capability_facts
from vgen.market.models import WorkflowManifest
from vgen.market.registry import package_digest


def test_h3_bootstrap_authorization_matches_the_bundled_package() -> None:
    root = Path(__file__).resolve().parents[2]
    package = root / "workflows/vgen/minimax-h3-8step/1.0.0"
    manifest = WorkflowManifest.load(package / "manifest.yaml")
    facts = comfyui_capability_facts(manifest, package)

    assert len(COMFYUI_BOOTSTRAP_WORKFLOWS) == 1
    authorization = COMFYUI_BOOTSTRAP_WORKFLOWS[0]
    assert authorization.workflow_ref == f"{manifest.id}@{manifest.version}"
    assert authorization.workflow_digest == f"sha256:{package_digest(package)}"
    assert authorization.model_digests == tuple(
        sorted(f"sha256:{model.sha256}" for model in facts.variant.models)
    )
    assert authorization.node_classes == tuple(sorted(facts.node_classes))


def test_bootstrap_policy_reconciles_replaced_and_removed_grants(tmp_path, monkeypatch) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    try:
        stamp = now()
        db.execute(
            """INSERT INTO users
               (id,display_name,root_signing_public_key,root_encryption_public_key,
                status,is_operator,created_at,updated_at)
               VALUES ('usr_bootstrap','Owner','sign-bootstrap','encrypt-bootstrap',
                       'active',0,?,?)""",
            (stamp, stamp),
        )
        repository = GatewayRepository(db)
        worker = repository.create_worker(
            owner_user_id="usr_bootstrap",
            manager_broker_id=None,
            name="Bootstrap Worker",
            signing_public_key="worker-sign-bootstrap",
            encryption_public_key="worker-encrypt-bootstrap",
            certificate=None,
            executor_type="comfyui",
            executor_version="1.0.0",
            capabilities={},
            capacity=1,
        )
        original = COMFYUI_BOOTSTRAP_WORKFLOWS[0]
        replacement = BootstrapWorkflowAuthorization(
            workflow_ref=original.workflow_ref,
            workflow_digest="sha256:" + "a" * 64,
            model_digests=("sha256:" + "b" * 64,),
            node_classes=("ReplacementNode",),
        )
        monkeypatch.setattr(
            repository_module, "COMFYUI_BOOTSTRAP_WORKFLOWS", (replacement,)
        )

        GatewayRepository(db)
        original_row = db.fetchone(
            """SELECT revoked_at FROM worker_workflow_authorizations
               WHERE worker_id=? AND workflow_digest=?""",
            (worker["id"], original.workflow_digest),
        )
        replacement_row = db.fetchone(
            """SELECT node_classes,revoked_at FROM worker_workflow_authorizations
               WHERE worker_id=? AND workflow_digest=?""",
            (worker["id"], replacement.workflow_digest),
        )
        assert original_row["revoked_at"] is not None
        assert replacement_row["revoked_at"] is None
        assert replacement_row["node_classes"] == '["ReplacementNode"]'
        assert (
            db.fetchone(
                """SELECT COUNT(*) AS n FROM worker_model_authorizations
                   WHERE worker_id=? AND model_digest=? AND revoked_at IS NULL""",
                (worker["id"], replacement.model_digests[0]),
            )["n"]
            == 1
        )
        assert (
            db.fetchone(
                """SELECT COUNT(*) AS n FROM worker_model_authorizations
                   WHERE worker_id=? AND model_digest IN (?,?,?,?,?) AND revoked_at IS NULL""",
                (worker["id"], *original.model_digests),
            )["n"]
            == 0
        )

        monkeypatch.setattr(repository_module, "COMFYUI_BOOTSTRAP_WORKFLOWS", ())
        GatewayRepository(db)
        assert (
            db.fetchone(
                """SELECT revoked_at FROM worker_workflow_authorizations
                   WHERE worker_id=? AND workflow_digest=?""",
                (worker["id"], replacement.workflow_digest),
            )["revoked_at"]
            is not None
        )
    finally:
        db.close()
