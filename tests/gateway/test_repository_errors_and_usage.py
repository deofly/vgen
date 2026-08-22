from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from vgen.crypto import (
    DeviceKeys,
    b64url_encode,
    derive_identity_keys,
    issue_device_certificate,
)
from vgen.gateway.database import GatewayDatabase, json_text, now
from vgen.gateway.repository import GatewayRepository, RepositoryError
from vgen.protocol.errors import ERROR_REGISTRY, ErrorCode
from vgen.protocol.ids import new_id
from vgen.protocol.user_enrollment import (
    build_user_registration_claim,
    sign_user_registration_claim,
)


def test_existing_v1_ledger_adds_reversal_reference_reason_and_unique_index(tmp_path) -> None:
    path = tmp_path / "legacy-v1.db"
    legacy = sqlite3.connect(path)
    legacy.executescript(
        """
        CREATE TABLE schema_meta (version INTEGER NOT NULL);
        INSERT INTO schema_meta(version) VALUES (1);
        CREATE TABLE usage_ledger (
            id TEXT PRIMARY KEY,
            attempt_id TEXT NOT NULL,
            entry_type TEXT NOT NULL CHECK(entry_type IN ('charge','reversal')),
            metrics TEXT NOT NULL,
            rate_snapshot TEXT NOT NULL,
            compute_microtokens INTEGER NOT NULL,
            traffic_microtokens INTEGER NOT NULL DEFAULT 0,
            total_microtokens INTEGER NOT NULL,
            billable INTEGER NOT NULL,
            responsibility TEXT NOT NULL,
            formula_version INTEGER NOT NULL,
            previous_hash TEXT,
            integrity_hash TEXT NOT NULL UNIQUE,
            created_at REAL NOT NULL
        );
        """
    )
    legacy.commit()
    legacy.close()

    db = GatewayDatabase(str(path))
    try:
        columns = {row["name"] for row in db.fetchall("PRAGMA table_info(usage_ledger)")}
        indexes = {row["name"]: row for row in db.fetchall("PRAGMA index_list(usage_ledger)")}
        assert {"reverses_ledger_id", "reversal_reason_code"} <= columns
        assert indexes["idx_ledger_one_reversal_per_charge"]["unique"] == 1
        assert indexes["idx_ledger_one_reversal_per_charge"]["partial"] == 1
    finally:
        db.close()


def _insert_user(db: GatewayDatabase, label: str) -> str:
    user_id = new_id("user")
    stamp = now()
    db.execute(
        """INSERT INTO users
           (id,display_name,root_signing_public_key,root_encryption_public_key,
            status,is_operator,created_at,updated_at)
           VALUES (?,?,?,?,'active',0,?,?)""",
        (user_id, label, f"sign-{label}", f"encrypt-{label}", stamp, stamp),
    )
    return user_id


def _insert_usage_entry(
    db: GatewayDatabase,
    *,
    workspace_id: str,
    pool_id: str,
    worker_id: str,
    provider_user_id: str,
    consumer_user_id: str | None,
    consumer_principal_type: str,
    consumer_principal_id: str,
    created_at: float,
    compute_microtokens: int = 1,
    traffic_microtokens: int = 0,
    billable: bool = True,
) -> str:
    task_id = new_id("task")
    attempt_id = new_id("attempt")
    ledger_id = new_id("usage_ledger")
    db.execute(
        """INSERT INTO tasks
           (id,workspace_id,pool_id,consumer_user_id,consumer_principal_type,
            consumer_principal_id,client_channel,workflow_ref,workflow_digest,
            executor_type,public_requirements,content_key_version,state,priority,
            created_at,finished_at,updated_at)
           VALUES (?,?,?,?,?,?,'cli','vgen/test@1.0.0',?,'fake','{}',1,
                   'succeeded',0,?,?,?)""",
        (
            task_id,
            workspace_id,
            pool_id,
            consumer_user_id,
            consumer_principal_type,
            consumer_principal_id,
            hashlib.sha256(task_id.encode()).hexdigest(),
            created_at,
            created_at,
            created_at,
        ),
    )
    db.execute(
        """INSERT INTO task_attempts
           (id,task_id,attempt_number,worker_id,provider_user_id,executor_type,
            executor_version,state,responsibility,rate_snapshot,fencing_token,
            reserved_at,finished_at)
           VALUES (?,?,1,?,?,'fake','1','succeeded','none','{}',?,?,?)""",
        (
            attempt_id,
            task_id,
            worker_id,
            provider_user_id,
            int(created_at * 1_000_000),
            created_at,
            created_at,
        ),
    )
    db.execute(
        """INSERT INTO usage_ledger
           (id,attempt_id,entry_type,metrics,rate_snapshot,compute_microtokens,
            traffic_microtokens,total_microtokens,billable,responsibility,
            formula_version,integrity_hash,created_at)
           VALUES (?,?,'charge',?,'{}',?,?,?,?,'none',1,?,?)""",
        (
            ledger_id,
            attempt_id,
            json_text({"gpu_active_ms": 1}),
            compute_microtokens,
            traffic_microtokens,
            compute_microtokens + traffic_microtokens,
            int(billable),
            hashlib.sha256(ledger_id.encode()).hexdigest(),
            created_at,
        ),
    )
    return task_id


def _insert_approved_allocation(
    db: GatewayDatabase,
    *,
    worker_id: str,
    workspace_id: str,
    pool_id: str,
    approved_by_user_id: str,
    status: str = "active",
) -> None:
    stamp = now()
    db.execute(
        """INSERT INTO worker_allocations
           (id,worker_id,workspace_id,pool_id,owner_consent_at,
            workspace_approved_at,approved_by_user_id,allocation_proof,status,
            created_at,updated_at,revoked_at)
           VALUES (?,?,?,?,?,?,?,'{}',?,?,?,?)""",
        (
            new_id("allocation"),
            worker_id,
            workspace_id,
            pool_id,
            stamp,
            stamp,
            approved_by_user_id,
            status,
            stamp,
            stamp,
            stamp if status == "revoked" else None,
        ),
    )


def _insert_running_attempt(
    db: GatewayDatabase,
    *,
    workspace_id: str,
    pool_id: str,
    worker_id: str,
    provider_user_id: str,
    consumer_user_id: str,
) -> tuple[str, str, int]:
    task_id = new_id("task")
    attempt_id = new_id("attempt")
    lease_id = new_id("lease")
    stamp = now()
    fencing_token = int(stamp * 1_000_000)
    rate_snapshot = json_text(
        {
            "rate_microtokens_per_gpu_second": 1_000_000,
            "traffic_microtokens_per_gib": 0,
            "workflow_multiplier_ppm": 1_000_000,
            "formula_version": 1,
        }
    )
    db.execute(
        """INSERT INTO tasks
           (id,workspace_id,pool_id,consumer_user_id,consumer_principal_type,
            consumer_principal_id,client_channel,workflow_ref,workflow_digest,
            executor_type,public_requirements,content_key_version,assigned_worker_id,
            state,priority,created_at,committed_at,updated_at)
           VALUES (?,?,?,?,?,'consumer-device','cli','vgen/test@1.0.0',?,'fake',
                   '{}',1,?,'running',0,?,?,?)""",
        (
            task_id,
            workspace_id,
            pool_id,
            consumer_user_id,
            "device",
            hashlib.sha256(task_id.encode()).hexdigest(),
            worker_id,
            stamp - 3,
            stamp - 3,
            stamp - 2,
        ),
    )
    db.execute(
        """INSERT INTO task_attempts
           (id,task_id,attempt_number,worker_id,provider_user_id,executor_type,
            executor_version,state,rate_snapshot,fencing_token,reserved_at,leased_at,
            started_at)
           VALUES (?,?,1,?,?,'fake','1','running',?,?,?,?,?)""",
        (
            attempt_id,
            task_id,
            worker_id,
            provider_user_id,
            rate_snapshot,
            fencing_token,
            stamp - 3,
            stamp - 2.5,
            stamp - 2,
        ),
    )
    db.execute(
        """INSERT INTO leases
           (id,attempt_id,worker_id,fencing_token,encrypted_tdk_envelope,issued_at,
            expires_at,heartbeat_at)
           VALUES (?,?,?,?,'{}',?,?,?)""",
        (
            lease_id,
            attempt_id,
            worker_id,
            fencing_token,
            stamp - 2.5,
            stamp + 60,
            stamp,
        ),
    )
    return task_id, attempt_id, fencing_token


def test_resource_errors_use_permanent_category_codes(tmp_path) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    repository = GatewayRepository(db)
    try:
        owner_id = _insert_user(db, "owner")
        workspace = repository.create_workspace(user_id=owner_id, name="Errors")
        owner_root = derive_identity_keys(b"resource-errors-owner-seed-0001!")
        owner_device = DeviceKeys.generate()
        owner_device_id = new_id("device")
        owner_certificate = issue_device_certificate(
            owner_root, owner_device, device_id=owner_device_id
        ).to_dict()
        stamp = now()
        db.execute(
            """UPDATE users
               SET root_signing_public_key=?,root_encryption_public_key=?,updated_at=?
               WHERE id=?""",
            (
                b64url_encode(owner_root.signing_public_bytes()),
                b64url_encode(owner_root.encryption_public_bytes()),
                stamp,
                owner_id,
            ),
        )
        db.execute(
            """INSERT INTO devices
               (id,user_id,name,signing_public_key,encryption_public_key,certificate,
                status,created_at,last_seen_at)
               VALUES (?,?,?,?,?,?,'active',?,?)""",
            (
                owner_device_id,
                owner_id,
                "owner-device",
                b64url_encode(owner_device.signing_public_bytes()),
                b64url_encode(owner_device.encryption_public_bytes()),
                json_text(owner_certificate),
                stamp,
                stamp,
            ),
        )
        application_id = new_id("application")
        application_claim = build_user_registration_claim(
            invite_id=application_id,
            display_name="owner",
            root_key_id=owner_root.root_key_id,
            root_signing_public_key=b64url_encode(owner_root.signing_public_bytes()),
            root_encryption_public_key=b64url_encode(owner_root.encryption_public_bytes()),
            device_id=owner_device_id,
            device_name="owner-device",
            device_signing_public_key=b64url_encode(owner_device.signing_public_bytes()),
            device_encryption_public_key=b64url_encode(owner_device.encryption_public_bytes()),
            device_certificate=owner_certificate,
        )
        application_proof = sign_user_registration_claim(
            owner_device.signing_private_key, application_claim
        )

        cases = (
            (
                lambda: repository.apply(
                    subject_user_id=owner_id,
                    subject_device_id=owner_device_id,
                    application_id=application_id,
                    workspace_id=new_id("workspace"),
                    pool_id=None,
                    kind="workspace_member",
                    claim=application_claim,
                    proof_signature=application_proof,
                    relationship="member",
                ),
                ErrorCode.WORKSPACE_NOT_FOUND,
            ),
            (
                lambda: repository.create_invite(
                    issuer_user_id=owner_id,
                    workspace_id=workspace["id"],
                    pool_id=None,
                    kind="worker_allocation",
                    method="direct_invite",
                    scopes=[],
                    relationship=None,
                    subject_key_fingerprint=None,
                    ttl_seconds=60,
                ),
                ErrorCode.ENROLLMENT_CLOSED,
            ),
            (
                lambda: repository.worker_heartbeat(worker_id=new_id("worker")),
                ErrorCode.WORKER_NOT_FOUND,
            ),
            (
                lambda: repository.get_allocation(
                    allocation_id=new_id("allocation"), user_id=owner_id
                ),
                ErrorCode.WORKER_ALLOCATION_NOT_FOUND,
            ),
            (
                lambda: repository.enrollment(new_id("enrollment")),
                ErrorCode.ENROLLMENT_NOT_FOUND,
            ),
            (
                lambda: repository.get_task(task_id=new_id("task"), user_id=owner_id),
                ErrorCode.TASK_NOT_FOUND,
            ),
            (
                lambda: repository.approve_rate(
                    rate_id=new_id("rate_card"), admin_user_id=owner_id
                ),
                ErrorCode.RATE_NOT_FOUND,
            ),
        )
        for operation, expected in cases:
            with pytest.raises(RepositoryError) as raised:
                operation()
            assert raised.value.code == int(expected)
            assert raised.value.name == expected.name
            assert expected in ERROR_REGISTRY

        worker = repository.create_worker(
            owner_user_id=owner_id,
            manager_broker_id=None,
            name="revoked",
            signing_public_key="worker-signing-key",
            encryption_public_key="worker-encryption-key",
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        db.execute("UPDATE workers SET status='revoked' WHERE id=?", (worker["id"],))
        with pytest.raises(RepositoryError) as revoked:
            repository.worker_heartbeat(worker_id=worker["id"])
        assert revoked.value.code == int(ErrorCode.WORKER_REVOKED)
        assert revoked.value.name == ErrorCode.WORKER_REVOKED.name

        rate = repository.propose_rate(
            worker_id=worker["id"],
            workspace_id=workspace["id"],
            user_id=owner_id,
            rate_microtokens_per_gpu_second=1_000_000,
            traffic_microtokens_per_gib=1,
        )
        with pytest.raises(RepositoryError) as traffic:
            repository.approve_rate(rate_id=rate["id"], admin_user_id=owner_id)
        assert traffic.value.code == int(ErrorCode.RATE_NOT_APPROVED)
        assert traffic.value.name == "TRAFFIC_BILLING_NOT_ENABLED"
    finally:
        db.close()


def test_repository_rejects_private_or_free_form_public_metadata() -> None:
    secret = "PRIVATE_PROMPT_repository_boundary"
    for operation, field in (
        (
            lambda: GatewayRepository._public_requirements({"prompt": secret}),
            "public_requirements",
        ),
        (
            lambda: GatewayRepository._artifact_media_metadata({"description": secret}),
            "media_metadata",
        ),
    ):
        with pytest.raises(RepositoryError) as raised:
            operation()
        assert raised.value.code == int(ErrorCode.VALIDATION_FAILED)
        assert raised.value.details == {"field": field, "reason": "unsupported_field"}
        assert secret not in str(raised.value)
        assert secret not in json.dumps(raised.value.details)


def test_usage_visibility_is_scoped_to_consumer_or_workspace_admin(tmp_path) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    repository = GatewayRepository(db)
    try:
        owner_id = _insert_user(db, "owner")
        admin_id = _insert_user(db, "admin")
        member_id = _insert_user(db, "member")
        provider_id = _insert_user(db, "provider-only")
        outsider_id = _insert_user(db, "outsider")
        workspace = repository.create_workspace(user_id=owner_id, name="Usage")
        pool = repository.create_pool(
            workspace_id=workspace["id"], user_id=owner_id, name="GPU", policy={}
        )
        stamp = now()
        db.execute(
            """INSERT INTO memberships(workspace_id,user_id,role,status,created_at)
               VALUES (?,?,'admin','active',?),(?,?,'member','active',?)""",
            (workspace["id"], admin_id, stamp, workspace["id"], member_id, stamp),
        )
        worker = repository.create_worker(
            owner_user_id=owner_id,
            manager_broker_id=None,
            name="provider",
            signing_public_key="usage-worker-signing-key",
            encryption_public_key="usage-worker-encryption-key",
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        member_worker = repository.create_worker(
            owner_user_id=member_id,
            manager_broker_id=None,
            name="member-provider",
            signing_public_key="member-worker-signing-key",
            encryption_public_key="member-worker-encryption-key",
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        provider_worker = repository.create_worker(
            owner_user_id=provider_id,
            manager_broker_id=None,
            name="provider-only",
            signing_public_key="provider-only-worker-signing-key",
            encryption_public_key="provider-only-worker-encryption-key",
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        _insert_approved_allocation(
            db,
            worker_id=member_worker["id"],
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            approved_by_user_id=owner_id,
        )
        # Historical provider access survives leaving the Pool, so a Worker-only
        # user can still reconcile attempts which already contributed resources.
        _insert_approved_allocation(
            db,
            worker_id=provider_worker["id"],
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            approved_by_user_id=owner_id,
            status="revoked",
        )
        service_id = new_id("service")
        db.execute(
            """INSERT INTO services
               (id,workspace_id,name,signing_public_key,encryption_public_key,scopes,
                status,created_by_user_id,created_at,updated_at)
               VALUES (?,?,?,?,?,'["usage:read"]','active',?,?,?)""",
            (
                service_id,
                workspace["id"],
                "automation",
                "service-signing-key",
                "service-encryption-key",
                owner_id,
                stamp,
                stamp,
            ),
        )

        owner_task = _insert_usage_entry(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=worker["id"],
            provider_user_id=owner_id,
            consumer_user_id=owner_id,
            consumer_principal_type="device",
            consumer_principal_id="owner-device",
            created_at=stamp + 1,
        )
        member_task = _insert_usage_entry(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=worker["id"],
            provider_user_id=owner_id,
            consumer_user_id=member_id,
            consumer_principal_type="device",
            consumer_principal_id="member-device",
            created_at=stamp + 2,
        )
        service_task = _insert_usage_entry(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=worker["id"],
            provider_user_id=owner_id,
            consumer_user_id=None,
            consumer_principal_type="service",
            consumer_principal_id=service_id,
            created_at=stamp + 3,
        )
        member_provider_task = _insert_usage_entry(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=member_worker["id"],
            provider_user_id=member_id,
            consumer_user_id=owner_id,
            consumer_principal_type="device",
            consumer_principal_id="owner-device",
            created_at=stamp + 4,
        )
        provider_only_task = _insert_usage_entry(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=provider_worker["id"],
            provider_user_id=provider_id,
            consumer_user_id=owner_id,
            consumer_principal_type="device",
            consumer_principal_id="owner-device",
            created_at=stamp + 5,
        )
        # A later re-offer clears the current approval fields, but the completed
        # Attempt remains proof that this provider previously served the Workspace.
        db.execute(
            """UPDATE worker_allocations
               SET workspace_approved_at=NULL,approved_by_user_id=NULL,
                   allocation_proof=NULL,status='pending_workspace',revoked_at=NULL
               WHERE worker_id=?""",
            (provider_worker["id"],),
        )

        owner_view = repository.usage(workspace_id=workspace["id"], user_id=owner_id, limit=100)
        admin_view = repository.usage(workspace_id=workspace["id"], user_id=admin_id, limit=100)
        member_view = repository.usage(workspace_id=workspace["id"], user_id=member_id, limit=100)
        service_view = repository.usage(
            workspace_id=workspace["id"],
            user_id=None,
            principal_type="service",
            principal_id=service_id,
            limit=100,
        )
        provider_view = repository.usage(
            workspace_id=workspace["id"], user_id=provider_id, limit=100
        )

        all_tasks = {
            owner_task,
            member_task,
            service_task,
            member_provider_task,
            provider_only_task,
        }
        assert {entry["task_id"] for entry in owner_view} == all_tasks
        assert {entry["task_id"] for entry in admin_view} == all_tasks
        assert {entry["task_id"] for entry in member_view} == {
            member_task,
            member_provider_task,
        }
        assert {entry["task_id"] for entry in service_view} == {service_task}
        assert {entry["task_id"] for entry in provider_view} == {provider_only_task}
        assert provider_view[0]["consumer_principal_id"] == "owner-device"
        assert provider_view[0]["client_channel"] == "cli"
        assert "encrypted_payload" not in provider_view[0]

        with pytest.raises(RepositoryError) as denied:
            repository.usage(workspace_id=workspace["id"], user_id=outsider_id, limit=100)
        assert denied.value.code == int(ErrorCode.PERMISSION_DENIED)
    finally:
        db.close()


def test_usage_reversal_is_append_only_admin_scoped_and_semantically_idempotent(
    tmp_path,
) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    repository = GatewayRepository(db)
    try:
        owner_id = _insert_user(db, "reversal-owner")
        member_id = _insert_user(db, "reversal-member")
        workspace = repository.create_workspace(user_id=owner_id, name="Reversal")
        other_workspace = repository.create_workspace(user_id=owner_id, name="Other")
        pool = repository.create_pool(
            workspace_id=workspace["id"], user_id=owner_id, name="GPU", policy={}
        )
        stamp = now()
        db.execute(
            """INSERT INTO memberships(workspace_id,user_id,role,status,created_at)
               VALUES (?,?,'member','active',?)""",
            (workspace["id"], member_id, stamp),
        )
        worker = repository.create_worker(
            owner_user_id=owner_id,
            manager_broker_id=None,
            name="reversal-worker",
            signing_public_key="reversal-worker-signing-key",
            encryption_public_key="reversal-worker-encryption-key",
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        task_id = _insert_usage_entry(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=worker["id"],
            provider_user_id=owner_id,
            consumer_user_id=owner_id,
            consumer_principal_type="device",
            consumer_principal_id="owner-device",
            created_at=stamp,
            compute_microtokens=7,
            traffic_microtokens=3,
        )
        charge = db.fetchone(
            """SELECT l.* FROM usage_ledger l
               JOIN task_attempts a ON a.id=l.attempt_id WHERE a.task_id=?""",
            (task_id,),
        )

        with pytest.raises(RepositoryError) as denied:
            repository.reverse_usage_charge(
                workspace_id=workspace["id"],
                ledger_id=charge["id"],
                user_id=member_id,
                reason_code="duplicate_charge",
            )
        assert denied.value.code == int(ErrorCode.PERMISSION_DENIED)

        with pytest.raises(RepositoryError) as wrong_workspace:
            repository.reverse_usage_charge(
                workspace_id=other_workspace["id"],
                ledger_id=charge["id"],
                user_id=owner_id,
                reason_code="duplicate_charge",
            )
        assert wrong_workspace.value.code == int(ErrorCode.VALIDATION_FAILED)
        assert wrong_workspace.value.http_status == 404

        reversal = repository.reverse_usage_charge(
            workspace_id=workspace["id"],
            ledger_id=charge["id"],
            user_id=owner_id,
            reason_code="duplicate_charge",
        )
        replay = repository.reverse_usage_charge(
            workspace_id=workspace["id"],
            ledger_id=charge["id"],
            user_id=owner_id,
            reason_code="rate_correction",
        )

        assert replay["id"] == reversal["id"]
        assert reversal["entry_type"] == "reversal"
        assert reversal["reverses_ledger_id"] == charge["id"]
        assert reversal["reversal_reason_code"] == "duplicate_charge"
        assert reversal["compute_microtokens"] == -7
        assert reversal["traffic_microtokens"] == -3
        assert reversal["total_microtokens"] == -10
        assert reversal["previous_hash"] == charge["integrity_hash"]
        stored_charge = db.fetchone(
            "SELECT compute_microtokens,total_microtokens FROM usage_ledger WHERE id=?",
            (charge["id"],),
        )
        assert stored_charge["compute_microtokens"] == 7
        assert stored_charge["total_microtokens"] == 10
        assert (
            db.fetchone(
                "SELECT COUNT(*) AS count FROM usage_ledger WHERE reverses_ledger_id=?",
                (charge["id"],),
            )["count"]
            == 1
        )
        assert (
            db.fetchone(
                "SELECT COUNT(*) AS count FROM audit_events WHERE action='usage.charge_reversed'"
            )["count"]
            == 1
        )

        with pytest.raises(RepositoryError) as non_charge:
            repository.reverse_usage_charge(
                workspace_id=workspace["id"],
                ledger_id=reversal["id"],
                user_id=owner_id,
                reason_code="duplicate_charge",
            )
        assert non_charge.value.code == int(ErrorCode.VALIDATION_FAILED)
        assert non_charge.value.http_status == 409

        nonbillable_task_id = _insert_usage_entry(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=worker["id"],
            provider_user_id=owner_id,
            consumer_user_id=owner_id,
            consumer_principal_type="device",
            consumer_principal_id="owner-device",
            created_at=stamp + 1,
            compute_microtokens=0,
            billable=False,
        )
        nonbillable = db.fetchone(
            """SELECT l.id FROM usage_ledger l
               JOIN task_attempts a ON a.id=l.attempt_id WHERE a.task_id=?""",
            (nonbillable_task_id,),
        )
        with pytest.raises(RepositoryError) as nonbillable_error:
            repository.reverse_usage_charge(
                workspace_id=workspace["id"],
                ledger_id=nonbillable["id"],
                user_id=owner_id,
                reason_code="platform_fault",
            )
        assert nonbillable_error.value.http_status == 409
    finally:
        db.close()


def test_worker_cannot_self_assign_consumer_billing_responsibility(tmp_path) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    repository = GatewayRepository(db)
    try:
        owner_id = _insert_user(db, "billing-owner")
        workspace = repository.create_workspace(user_id=owner_id, name="Billing")
        pool = repository.create_pool(
            workspace_id=workspace["id"], user_id=owner_id, name="GPU", policy={}
        )
        worker = repository.create_worker(
            owner_user_id=owner_id,
            manager_broker_id=None,
            name="billing-worker",
            signing_public_key="billing-worker-signing-key",
            encryption_public_key="billing-worker-encryption-key",
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        _task_id, attempt_id, fencing_token = _insert_running_attempt(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=worker["id"],
            provider_user_id=owner_id,
            consumer_user_id=owner_id,
        )
        reported_metrics = {
            "gpu_active_ms": 100_000,
            "gpu_count": 1,
            "gateway_wall_ms": 999_999,
        }

        with pytest.raises(RepositoryError) as forged:
            repository.finish_attempt(
                attempt_id=attempt_id,
                worker_id=worker["id"],
                fencing_token=fencing_token,
                succeeded=False,
                output_artifacts=[],
                metrics=reported_metrics,
                worker_signature="signed-worker-report",
                failure_code=int(ErrorCode.GPU_OUT_OF_MEMORY),
                responsibility="consumer",
                safe_failure_details={},
            )
        assert forged.value.code == int(ErrorCode.USAGE_REPORT_INVALID)
        assert (
            db.fetchone(
                "SELECT COUNT(*) AS count FROM usage_ledger WHERE attempt_id=?", (attempt_id,)
            )["count"]
            == 0
        )
        assert (
            db.fetchone("SELECT state FROM task_attempts WHERE id=?", (attempt_id,))["state"]
            == "running"
        )

        finished = repository.finish_attempt(
            attempt_id=attempt_id,
            worker_id=worker["id"],
            fencing_token=fencing_token,
            succeeded=False,
            output_artifacts=[],
            metrics=reported_metrics,
            worker_signature="signed-worker-report",
            failure_code=int(ErrorCode.GPU_OUT_OF_MEMORY),
            responsibility="provider",
            safe_failure_details={},
        )
        assert finished["state"] == "failed"
        event_metrics = json.loads(
            db.fetchone("SELECT metrics FROM usage_events WHERE attempt_id=?", (attempt_id,))[
                "metrics"
            ]
        )
        ledger = db.fetchone("SELECT * FROM usage_ledger WHERE attempt_id=?", (attempt_id,))
        ledger_metrics = json.loads(ledger["metrics"])
        assert event_metrics == reported_metrics
        assert ledger_metrics["gateway_wall_ms"] < 10_000
        assert set(ledger_metrics["anomaly_flags"]) == {
            "gateway_wall_report_mismatch",
            "gpu_active_exceeds_observed_capacity",
        }
        assert ledger["responsibility"] == "provider"
        assert ledger["billable"] == 0
        assert ledger["total_microtokens"] == 0

        assert GatewayRepository._canonical_attempt_outcome(
            succeeded=False,
            failure_code=int(ErrorCode.DECRYPTION_FAILED),
            reported_responsibility="platform",
        ) == (int(ErrorCode.DECRYPTION_FAILED), "platform")
        with pytest.raises(RepositoryError):
            GatewayRepository._canonical_attempt_outcome(
                succeeded=False,
                failure_code=999_999,
                reported_responsibility="platform",
            )
    finally:
        db.close()


def test_cancellation_before_execution_releases_lease_without_usage(tmp_path) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    repository = GatewayRepository(db)
    try:
        owner_id = _insert_user(db, "prestart-cancel-owner")
        workspace = repository.create_workspace(user_id=owner_id, name="Prestart cancel")
        pool = repository.create_pool(
            workspace_id=workspace["id"], user_id=owner_id, name="GPU", policy={}
        )
        worker = repository.create_worker(
            owner_user_id=owner_id,
            manager_broker_id=None,
            name="prestart-worker",
            signing_public_key="prestart-signing-key",
            encryption_public_key="prestart-encryption-key",
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        task_id, attempt_id, fencing_token = _insert_running_attempt(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=worker["id"],
            provider_user_id=owner_id,
            consumer_user_id=owner_id,
        )
        db.execute("UPDATE tasks SET state='reserved',finished_at=NULL WHERE id=?", (task_id,))
        db.execute(
            "UPDATE task_attempts SET state='leased',started_at=NULL WHERE id=?", (attempt_id,)
        )

        assert repository.cancel_task(task_id=task_id, user_id=owner_id) == {
            "task_id": task_id,
            "state": "cancelled",
        }
        assert (
            db.fetchone("SELECT state FROM task_attempts WHERE id=?", (attempt_id,))["state"]
            == "cancelled"
        )
        assert (
            db.fetchone("SELECT released_at FROM leases WHERE attempt_id=?", (attempt_id,))[
                "released_at"
            ]
            is not None
        )
        assert (
            db.fetchone(
                "SELECT COUNT(*) AS count FROM usage_events WHERE attempt_id=?", (attempt_id,)
            )["count"]
            == 0
        )
        assert (
            db.fetchone(
                "SELECT COUNT(*) AS count FROM usage_ledger WHERE attempt_id=?", (attempt_id,)
            )["count"]
            == 0
        )

        # The exact fenced Worker may acknowledge the pre-start directive, but
        # cannot turn it into a billable terminal report.
        acknowledged = repository.finish_attempt(
            attempt_id=attempt_id,
            worker_id=worker["id"],
            fencing_token=fencing_token,
            succeeded=False,
            output_artifacts=[],
            metrics={"executor_wall_ms": 0, "gpu_count": 1},
            worker_signature="signed-cancel-ack",
            failure_code=int(ErrorCode.EXECUTION_CANCELLED),
            responsibility="consumer",
            safe_failure_details={},
        )
        assert acknowledged["state"] == "cancelled"
        assert (
            db.fetchone(
                "SELECT COUNT(*) AS count FROM usage_ledger WHERE attempt_id=?", (attempt_id,)
            )["count"]
            == 0
        )
    finally:
        db.close()


def test_running_cancellation_waits_for_signed_usage_and_charges_once(tmp_path) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    repository = GatewayRepository(db)
    try:
        owner_id = _insert_user(db, "running-cancel-owner")
        workspace = repository.create_workspace(user_id=owner_id, name="Running cancel")
        pool = repository.create_pool(
            workspace_id=workspace["id"], user_id=owner_id, name="GPU", policy={}
        )
        worker = repository.create_worker(
            owner_user_id=owner_id,
            manager_broker_id=None,
            name="running-worker",
            signing_public_key="running-signing-key",
            encryption_public_key="running-encryption-key",
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        task_id, attempt_id, fencing_token = _insert_running_attempt(
            db,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            worker_id=worker["id"],
            provider_user_id=owner_id,
            consumer_user_id=owner_id,
        )

        with pytest.raises(RepositoryError) as worker_forged_cancellation:
            repository.finish_attempt(
                attempt_id=attempt_id,
                worker_id=worker["id"],
                fencing_token=fencing_token,
                succeeded=False,
                output_artifacts=[],
                metrics={"executor_wall_ms": 1_500, "gpu_count": 1},
                worker_signature="signed-forged-cancel",
                failure_code=int(ErrorCode.EXECUTION_CANCELLED),
                responsibility="consumer",
                safe_failure_details={},
            )
        assert worker_forged_cancellation.value.code == int(ErrorCode.USAGE_REPORT_INVALID)
        assert (
            db.fetchone("SELECT state FROM task_attempts WHERE id=?", (attempt_id,))["state"]
            == "running"
        )

        repository.cancel_task(task_id=task_id, user_id=owner_id)
        assert (
            db.fetchone("SELECT state FROM task_attempts WHERE id=?", (attempt_id,))["state"]
            == "running"
        )
        assert (
            db.fetchone("SELECT released_at FROM leases WHERE attempt_id=?", (attempt_id,))[
                "released_at"
            ]
            is None
        )
        directive = repository.heartbeat_attempt(
            attempt_id=attempt_id,
            worker_id=worker["id"],
            fencing_token=fencing_token,
            ttl_seconds=60,
            started=False,
        )
        assert directive["cancelled"] is True

        report = dict(
            attempt_id=attempt_id,
            worker_id=worker["id"],
            fencing_token=fencing_token,
            succeeded=False,
            output_artifacts=[],
            metrics={"executor_wall_ms": 1_500, "gpu_count": 1},
            worker_signature="signed-running-cancel",
            failure_code=int(ErrorCode.EXECUTION_CANCELLED),
            responsibility="consumer",
            safe_failure_details={},
        )
        finished = repository.finish_attempt(**report)
        assert finished["state"] == "cancelled"
        repeated = repository.finish_attempt(**report)
        assert repeated == finished

        ledger = db.fetchone("SELECT * FROM usage_ledger WHERE attempt_id=?", (attempt_id,))
        assert ledger["billable"] == 1
        assert ledger["responsibility"] == "consumer"
        assert ledger["compute_microtokens"] == 1_500_000
        metrics = json.loads(ledger["metrics"])
        assert metrics["gpu_active_ms"] == 1_500
        assert "cancelled_gpu_active_derived_from_executor_wall" in metrics["anomaly_flags"]
        assert (
            db.fetchone(
                "SELECT COUNT(*) AS count FROM usage_events WHERE attempt_id=?", (attempt_id,)
            )["count"]
            == 1
        )
        assert (
            db.fetchone(
                "SELECT COUNT(*) AS count FROM usage_ledger WHERE attempt_id=?", (attempt_id,)
            )["count"]
            == 1
        )

        with pytest.raises(RepositoryError) as late_success:
            repository.finish_attempt(
                **{
                    **report,
                    "succeeded": True,
                    "failure_code": None,
                    "responsibility": "none",
                }
            )
        assert late_success.value.code == int(ErrorCode.LEASE_LOST)
    finally:
        db.close()


@pytest.mark.parametrize(
    "native",
    [
        {"nested": {"value": 1}},
        {"sequence": [1, 2]},
        {"label": "not-a-measurement"},
        {"nan": float("nan")},
        {"infinite": float("inf")},
        {"too_large": 10**19},
        {"bad key": 1},
        {"x" * 65: 1},
        {index: index for index in range(2)},
    ],
)
def test_native_usage_rejects_unbounded_or_non_scalar_values(native) -> None:
    with pytest.raises(RepositoryError) as raised:
        GatewayRepository._validate_usage_metrics({"native": native})
    assert raised.value.code == int(ErrorCode.USAGE_REPORT_INVALID)


def test_native_usage_accepts_only_bounded_flat_metrics() -> None:
    native = {
        "cuda.utilization": 92.5,
        "cache_hit": True,
        "optional": None,
        "temperature_delta": -2,
    }
    assert GatewayRepository._validate_usage_metrics({"native": native}) == {"native": native}

    oversized = {f"metric_{index:02d}_" + "x" * 54: 10**18 for index in range(64)}
    with pytest.raises(RepositoryError) as raised:
        GatewayRepository._validate_usage_metrics({"native": oversized})
    assert raised.value.code == int(ErrorCode.USAGE_REPORT_INVALID)


def test_worker_failure_details_cannot_persist_task_plaintext_or_urls() -> None:
    prompt = "private prompt with customer name"
    assert GatewayRepository._canonical_failure_details(
        {
            "prompt": prompt,
            "reason": prompt,
            "upstream": "https://storage.example/signed?token=secret",
            "error_type": "ComfyProtocolError",
            "status_code": 502,
            "match_count": 2,
            "nested": {"prompt": prompt},
        }
    ) == {
        "error_type": "ComfyProtocolError",
        "match_count": 2,
        "status_code": 502,
    }
