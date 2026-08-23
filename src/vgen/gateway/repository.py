"""Control-plane repositories and atomic scheduling operations."""

from __future__ import annotations

import hashlib
import json
import math
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version

from vgen.crypto import (
    b64url_decode,
    build_allocation_proof_payload,
    canonical_json,
    device_key_id,
    root_signing_key_id,
    verify_allocation_proof,
    verify_device_certificate,
    verify_key_manifest,
    verify_message,
)
from vgen.protocol.errors import ErrorCode, get_error_spec
from vgen.protocol.user_enrollment import (
    verify_user_registration_claim,
    verify_workspace_recipient_admission,
    workspace_recipient_admission_digest,
)

from .database import (
    WORKER_ONLINE_WINDOW_SECONDS,
    GatewayDatabase,
    json_text,
    new_id,
    now,
    row_dict,
)
from .public_metadata import (
    PublicMetadataError,
    validate_artifact_media_metadata,
    validate_public_requirements,
)


@dataclass(slots=True)
class RepositoryError(Exception):
    code: int
    name: str
    message: str
    http_status: int = 400
    retry_action: str = "none"
    responsibility: str = "none"
    details: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message


FORBIDDEN = int(ErrorCode.PERMISSION_DENIED)
TASK_STATE_CONFLICT = int(ErrorCode.TASK_STATE_CONFLICT)
TASK_NOT_FOUND = int(ErrorCode.TASK_NOT_FOUND)
NO_ELIGIBLE_WORKER = int(ErrorCode.NO_ELIGIBLE_WORKER)
WORKER_OFFLINE = int(ErrorCode.WORKER_OFFLINE)
WORKER_DRAINING = int(ErrorCode.WORKER_DRAINING)
WORKER_REVOKED = int(ErrorCode.WORKER_REVOKED)
WORKER_NOT_FOUND = int(ErrorCode.WORKER_NOT_FOUND)
WORKER_MAINTENANCE_JOB_NOT_FOUND = int(ErrorCode.WORKER_MAINTENANCE_JOB_NOT_FOUND)
WORKER_MAINTENANCE_STATE_CONFLICT = int(ErrorCode.WORKER_MAINTENANCE_STATE_CONFLICT)
WORKSPACE_NOT_FOUND = int(ErrorCode.WORKSPACE_NOT_FOUND)
POOL_NOT_FOUND = int(ErrorCode.POOL_NOT_FOUND)
WORKER_ALLOCATION_NOT_FOUND = int(ErrorCode.WORKER_ALLOCATION_NOT_FOUND)
INVITE_INVALID_OR_EXPIRED = int(ErrorCode.INVITE_INVALID_OR_EXPIRED)
ENROLLMENT_APPROVAL_REQUIRED = int(ErrorCode.ENROLLMENT_APPROVAL_REQUIRED)
ENROLLMENT_NOT_FOUND = int(ErrorCode.ENROLLMENT_NOT_FOUND)
LEASE_LOST = int(ErrorCode.LEASE_LOST)
MAINTENANCE_LEASE_LOST = int(ErrorCode.MAINTENANCE_LEASE_LOST)
RESERVATION_EXPIRED = int(ErrorCode.RESERVATION_EXPIRED)
RATE_NOT_APPROVED = int(ErrorCode.RATE_NOT_APPROVED)
RATE_NOT_FOUND = int(ErrorCode.RATE_NOT_FOUND)
KEY_RECIPIENT_NOT_FOUND = int(ErrorCode.KEY_RECIPIENT_NOT_FOUND)
VALIDATION_FAILED = int(ErrorCode.VALIDATION_FAILED)
SIGNATURE_INVALID = int(ErrorCode.SIGNATURE_INVALID)
DEVICE_CERTIFICATE_INVALID = int(ErrorCode.DEVICE_CERTIFICATE_INVALID)
ALLOCATION_PROOF_INVALID = int(ErrorCode.ALLOCATION_PROOF_INVALID)
IDEMPOTENCY_CONFLICT = int(ErrorCode.IDEMPOTENCY_CONFLICT)

_NATIVE_USAGE_KEY_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
)
_NATIVE_USAGE_MAX_ENTRIES = 64
_NATIVE_USAGE_MAX_KEY_LENGTH = 64
_NATIVE_USAGE_MAX_ABSOLUTE_NUMBER = 10**18
_NATIVE_USAGE_MAX_SERIALIZED_BYTES = 4096
_USAGE_MAX_WALL_MS = 30 * 24 * 60 * 60 * 1000
_SAFE_FAILURE_DETAIL_KEYS = frozenset(
    {
        "error_type",
        "executor_type",
        "field",
        "input",
        "operation",
        "payload_format",
        "phase",
        "reason",
    }
)
_SAFE_FAILURE_DETAIL_NUMERIC_KEYS = frozenset({"match_count", "status_code"})
_SAFE_FAILURE_DETAIL_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:/-"
)

SERVICE_SCOPES = frozenset({"task:submit", "task:read", "task:cancel", "usage:read"})
USAGE_REVERSAL_REASON_CODES = frozenset(
    {
        "duplicate_charge",
        "rate_correction",
        "provider_fault",
        "platform_fault",
        "consumer_refund",
    }
)

_MAINTENANCE_ACTIVE_STATES = frozenset(
    {"awaiting_upload", "queued", "leased", "running", "restarting"}
)
_MAINTENANCE_SCHEDULING_BLOCK_STATES = frozenset(
    {"queued", "leased", "running", "restarting"}
)
_MAINTENANCE_LEASE_STATES = frozenset({"leased", "running", "restarting"})
_MAINTENANCE_TERMINAL_STATES = frozenset(
    {"succeeded", "failed", "cancelled", "expired"}
)
_WORKER_ENROLLMENT_CONTEXT = b"vgen-worker-enrollment-v1"


class GatewayRepository:
    def __init__(self, db: GatewayDatabase) -> None:
        self.db = db

    @staticmethod
    def _public_requirements(value: object) -> dict[str, Any]:
        try:
            return validate_public_requirements(value)
        except PublicMetadataError as exc:
            raise RepositoryError(
                VALIDATION_FAILED,
                "VALIDATION_FAILED",
                "Public scheduling requirements are invalid.",
                422,
                details={"field": "public_requirements", "reason": exc.reason},
            ) from exc

    @staticmethod
    def _artifact_media_metadata(value: object) -> dict[str, Any]:
        try:
            return validate_artifact_media_metadata(value)
        except PublicMetadataError as exc:
            raise RepositoryError(
                VALIDATION_FAILED,
                "VALIDATION_FAILED",
                "Artifact media metadata is invalid.",
                422,
                details={"field": "media_metadata", "reason": exc.reason},
            ) from exc

    @staticmethod
    def _matches_requirements(worker: sqlite3.Row, requirements: dict[str, Any]) -> bool:
        def identifier_set(value: object) -> set[str] | None:
            if value is None:
                return set()
            if not isinstance(value, list):
                return None
            identifiers: set[str] = set()
            for item in value:
                if isinstance(item, str) and item:
                    identifier = item
                elif isinstance(item, dict):
                    identifier = next(
                        (
                            str(item[key])
                            for key in ("sha256", "digest", "id", "filename")
                            if item.get(key)
                        ),
                        "",
                    )
                else:
                    return None
                if not identifier:
                    return None
                if len(identifier) == 64 and all(
                    character in "0123456789abcdefABCDEF" for character in identifier
                ):
                    identifier = "sha256:" + identifier.lower()
                identifiers.add(identifier)
            return identifiers

        def required_integer(name: str) -> int | None:
            value = requirements.get(name)
            if value is None:
                return 0
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return None
            return value

        def available_bytes(name: str) -> int:
            direct = nested.get(name)
            if isinstance(direct, int) and not isinstance(direct, bool) and direct >= 0:
                return direct
            return 0

        capabilities = json.loads(worker["capabilities"] or "{}")
        executors = capabilities.get("executors")
        if not isinstance(executors, list):
            return False
        descriptor = next(
            (
                item
                for item in executors
                if isinstance(item, dict) and item.get("type") == worker["executor_type"]
            ),
            None,
        )
        if descriptor is None:
            return False
        operation = requirements.get("operation")
        if operation and operation not in descriptor.get("operations", []):
            return False
        payload_format = requirements.get("payload_format")
        if payload_format and payload_format not in descriptor.get("payload_formats", []):
            return False
        minimum_executor_version = requirements.get("executor_min_version")
        if minimum_executor_version is not None:
            actual_executor_version = descriptor.get("version")
            if not isinstance(minimum_executor_version, str) or not isinstance(
                actual_executor_version, str
            ):
                return False
            try:
                if Version(actual_executor_version) < Version(minimum_executor_version):
                    return False
            except InvalidVersion:
                return False
        nested = (
            descriptor.get("capabilities")
            if isinstance(descriptor.get("capabilities"), dict)
            else {}
        )
        minimum_runtime_version = requirements.get("runtime_min_version")
        if minimum_runtime_version is not None:
            actual_runtime_version = nested.get("runtime_version")
            if not isinstance(minimum_runtime_version, str) or not isinstance(
                actual_runtime_version, str
            ):
                return False
            try:
                if Version(actual_runtime_version) < Version(minimum_runtime_version):
                    return False
            except InvalidVersion:
                return False
        required_models = identifier_set(
            requirements.get("model_digests", requirements.get("models"))
        )
        available_models = identifier_set(nested.get("model_digests", nested.get("models")))
        if required_models is None or available_models is None:
            return False
        if not required_models <= available_models:
            return False

        minimum_vram = required_integer("min_vram_bytes")
        minimum_ram = required_integer("min_ram_bytes")
        if minimum_vram is None or minimum_ram is None:
            return False
        vram_bytes = available_bytes("vram_bytes")
        gpus = nested.get("gpus")
        if isinstance(gpus, list):
            for gpu in gpus:
                if not isinstance(gpu, dict):
                    continue
                raw_bytes = gpu.get("vram_bytes", gpu.get("vram_total"))
                if isinstance(raw_bytes, int) and not isinstance(raw_bytes, bool):
                    vram_bytes = max(vram_bytes, raw_bytes)
                raw_megabytes = gpu.get("vram_total_mb")
                if isinstance(raw_megabytes, (int, float)) and not isinstance(raw_megabytes, bool):
                    vram_bytes = max(vram_bytes, int(raw_megabytes * 1024 * 1024))
        ram_bytes = available_bytes("ram_bytes")
        system = nested.get("system")
        if isinstance(system, dict):
            raw_ram = system.get("ram_bytes", system.get("ram_total"))
            if isinstance(raw_ram, int) and not isinstance(raw_ram, bool):
                ram_bytes = max(ram_bytes, raw_ram)
        return vram_bytes >= minimum_vram and ram_bytes >= minimum_ram

    @staticmethod
    def _task_candidate_rows(
        conn: sqlite3.Connection | GatewayDatabase,
        *,
        pool_id: str,
        executor_type: str,
        stamp: float,
    ) -> list[sqlite3.Row]:
        """Return the same ordered, capacity-aware candidate set used by prepare."""

        sql = """SELECT w.*,a.id AS allocation_id,a.allocation_proof AS allocation_proof,
                      a.approved_by_user_id AS allocation_approved_by,
                      a.owner_consent_at AS allocation_owner_consent_at
               FROM workers w JOIN worker_allocations a ON a.worker_id=w.id
               WHERE a.pool_id=? AND a.status='active' AND a.allocation_proof IS NOT NULL
                 AND w.status='active'
                 AND NOT EXISTS (
                   SELECT 1 FROM worker_maintenance_jobs mj
                   WHERE mj.worker_id=w.id
                     AND mj.state IN ('queued','leased','running','restarting')
                 )
                 AND w.executor_type=?
                 AND w.last_seen_at>?
                 AND (SELECT COUNT(*) FROM task_attempts ta JOIN tasks active_task ON active_task.id=ta.task_id
                      WHERE ta.worker_id=w.id AND ta.state IN ('reserved','leased','running')
                        AND (active_task.reservation_expires_at IS NULL OR active_task.reservation_expires_at>?)) < w.capacity
               ORDER BY COALESCE(w.last_seen_at,0) DESC,w.created_at LIMIT 50"""
        args = (
            pool_id,
            executor_type,
            stamp - WORKER_ONLINE_WINDOW_SECONDS,
            stamp,
        )
        if isinstance(conn, GatewayDatabase):
            return conn.fetchall(sql, args)
        return conn.execute(sql, args).fetchall()

    @staticmethod
    def _has_available_allocated_worker(
        conn: sqlite3.Connection | GatewayDatabase,
        *,
        pool_id: str,
        stamp: float,
    ) -> bool:
        """Check availability without exposing or filtering on an Executor."""

        sql = """SELECT 1
                   FROM workers w JOIN worker_allocations a ON a.worker_id=w.id
                   WHERE a.pool_id=? AND a.status='active' AND a.allocation_proof IS NOT NULL
                     AND w.status='active'
                     AND NOT EXISTS (
                       SELECT 1 FROM worker_maintenance_jobs mj
                       WHERE mj.worker_id=w.id
                         AND mj.state IN ('queued','leased','running','restarting')
                     )
                     AND w.last_seen_at>?
                     AND (SELECT COUNT(*) FROM task_attempts ta
                          JOIN tasks active_task ON active_task.id=ta.task_id
                          WHERE ta.worker_id=w.id
                            AND ta.state IN ('reserved','leased','running')
                            AND (active_task.reservation_expires_at IS NULL
                                 OR active_task.reservation_expires_at>?)) < w.capacity
                   LIMIT 1"""
        args = (pool_id, stamp - WORKER_ONLINE_WINDOW_SECONDS, stamp)
        if isinstance(conn, GatewayDatabase):
            return conn.fetchone(sql, args) is not None
        return conn.execute(sql, args).fetchone() is not None

    @staticmethod
    def _expire_reservations(conn: sqlite3.Connection, stamp: float) -> None:
        expired_tasks = conn.execute(
            """SELECT id FROM tasks
               WHERE reservation_expires_at<=? AND state IN ('prepared','committed','queued','rekey_required')""",
            (stamp,),
        ).fetchall()
        if not expired_tasks:
            return
        task_ids = [row["id"] for row in expired_tasks]
        encoded_task_ids = json_text(task_ids)
        conn.execute(
            """UPDATE task_attempts SET state='expired',finished_at=?
               WHERE task_id IN (SELECT value FROM json_each(?))
                 AND state IN ('reserved','leased')""",
            (stamp, encoded_task_ids),
        )
        conn.execute(
            """UPDATE leases SET released_at=? WHERE attempt_id IN
                 (SELECT id FROM task_attempts
                  WHERE task_id IN (SELECT value FROM json_each(?)))
                 AND released_at IS NULL""",
            (stamp, encoded_task_ids),
        )
        conn.execute(
            """UPDATE tasks SET state='expired',finished_at=?,updated_at=?
               WHERE id IN (SELECT value FROM json_each(?))""",
            (stamp, stamp, encoded_task_ids),
        )

    @staticmethod
    def _enqueue_task_rekey_command(
        conn: sqlite3.Connection,
        *,
        task_id: str,
        source_attempt_id: str,
        reason: str,
        stamp: float,
    ) -> int:
        """Queue one metadata-only rekey command for the freshest active Broker.

        A task is routed to at most one Broker Device for a given failed
        Attempt.  This prevents two devices from racing to replace the same
        reservation while still allowing a later failed Attempt to create a
        new command.
        """

        task = conn.execute(
            """SELECT id,workspace_id,consumer_user_id,content_key_version
               FROM tasks WHERE id=? AND state='rekey_required'""",
            (task_id,),
        ).fetchone()
        if task is None or not task["consumer_user_id"]:
            return 0
        broker_device = conn.execute(
            """SELECT bd.id FROM broker_devices bd
               JOIN brokers b ON b.id=bd.broker_id
               JOIN devices d ON d.id=bd.device_id
               WHERE b.owner_user_id=? AND b.status='active'
                 AND bd.status='active' AND d.status='active'
                 AND d.last_seen_at IS NOT NULL AND d.last_seen_at>=?
               ORDER BY d.last_seen_at DESC,bd.created_at DESC LIMIT 1""",
            (task["consumer_user_id"], stamp - 300),
        ).fetchone()
        if broker_device is None:
            return 0
        command_key = f"task_rekey:{task_id}:{source_attempt_id}"
        payload = {
            "version": 1,
            "task_id": task_id,
            "workspace_id": task["workspace_id"],
            "key_version": int(task["content_key_version"]),
            "source_attempt_id": source_attempt_id,
            "reason": reason,
        }
        cursor = conn.execute(
            """INSERT INTO broker_commands
               (id,broker_device_id,command_key,command_type,payload,state,created_at,expires_at)
               VALUES (?,?,?,'task_rekey',?,'pending',?,?)
               ON CONFLICT(command_key)
               WHERE command_key IS NOT NULL DO UPDATE SET
                 payload=CASE WHEN broker_commands.state='expired' THEN excluded.payload
                              ELSE broker_commands.payload END,
                 broker_device_id=CASE WHEN broker_commands.state='expired'
                                       THEN excluded.broker_device_id
                                       ELSE broker_commands.broker_device_id END,
                 state=CASE WHEN broker_commands.state='expired' THEN 'pending'
                            ELSE broker_commands.state END,
                 created_at=CASE WHEN broker_commands.state='expired' THEN excluded.created_at
                                 ELSE broker_commands.created_at END,
                 expires_at=CASE WHEN broker_commands.state='expired' THEN excluded.expires_at
                                 ELSE broker_commands.expires_at END""",
            (
                new_id("bcm"),
                broker_device["id"],
                command_key,
                json_text(payload),
                stamp,
                stamp + 3600,
            ),
        )
        return max(0, cursor.rowcount)

    @classmethod
    def _ensure_rekey_commands(
        cls,
        conn: sqlite3.Connection,
        stamp: float,
        *,
        consumer_user_id: str | None = None,
    ) -> int:
        sql = """SELECT t.id,
                        (SELECT a.id FROM task_attempts a WHERE a.task_id=t.id
                         ORDER BY a.attempt_number DESC LIMIT 1) AS source_attempt_id
                 FROM tasks t
                 WHERE t.state='rekey_required' AND t.consumer_user_id IS NOT NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM task_attempts active
                     WHERE active.task_id=t.id AND active.state='reserved'
                       AND t.reservation_expires_at>?
                   )"""
        args: list[Any] = [stamp]
        if consumer_user_id is not None:
            sql += " AND t.consumer_user_id=?"
            args.append(consumer_user_id)
        queued = 0
        for task in conn.execute(sql, tuple(args)).fetchall():
            source_attempt_id = str(task["source_attempt_id"] or "none")
            queued += cls._enqueue_task_rekey_command(
                conn,
                task_id=task["id"],
                source_attempt_id=source_attempt_id,
                reason="rekey_required",
                stamp=stamp,
            )
        return queued

    @classmethod
    def _expire_leases(cls, conn: sqlite3.Connection, stamp: float) -> int:
        expired = conn.execute(
            """SELECT l.attempt_id,l.worker_id,a.task_id FROM leases l
               JOIN task_attempts a ON a.id=l.attempt_id
               WHERE l.released_at IS NULL AND l.expires_at<=?""",
            (stamp,),
        ).fetchall()
        transitioned = 0
        for row in expired:
            conn.execute(
                "UPDATE leases SET released_at=? WHERE attempt_id=?", (stamp, row["attempt_id"])
            )
            conn.execute(
                """UPDATE task_attempts SET state='expired',responsibility='platform',failure_code=?,finished_at=?
                   WHERE id=? AND state IN ('leased','running')""",
                (LEASE_LOST, stamp, row["attempt_id"]),
            )
            cursor = conn.execute(
                """UPDATE tasks SET state='rekey_required',updated_at=?
                   WHERE id=? AND state IN ('reserved','running')""",
                (stamp, row["task_id"]),
            )
            if cursor.rowcount:
                transitioned += 1
                cls._enqueue_task_rekey_command(
                    conn,
                    task_id=row["task_id"],
                    source_attempt_id=row["attempt_id"],
                    reason="lease_expired",
                    stamp=stamp,
                )
        cls._finalize_drained_workers(conn, stamp)
        return transitioned

    @staticmethod
    def _expire_maintenance_jobs(conn: sqlite3.Connection, stamp: float) -> int:
        """Fence abandoned maintenance leases and expire their signed intent window."""

        expired = conn.execute(
            """UPDATE worker_maintenance_jobs
               SET state='expired',completed_at=?,updated_at=?,lease_session_id=NULL,
                   lease_expires_at=NULL
               WHERE state IN ('awaiting_upload','queued','leased','running','restarting')
                 AND expires_at<=?""",
            (stamp, stamp, stamp),
        ).rowcount
        # A process crash must not strand a job until its longer authorization
        # expiry. Requeue with the old fencing token retained; the next claim
        # increments it, so a late report from the abandoned process is denied.
        conn.execute(
            """UPDATE worker_maintenance_jobs
               SET state='queued',lease_session_id=NULL,lease_expires_at=NULL,
                   heartbeat_at=NULL,updated_at=?
               WHERE state IN ('leased','running','restarting')
                 AND lease_expires_at IS NOT NULL AND lease_expires_at<=?
                 AND expires_at>?""",
            (stamp, stamp, stamp),
        )
        return max(0, expired)

    @staticmethod
    def _finalize_drained_workers(conn: sqlite3.Connection, stamp: float) -> int:
        drained = conn.execute(
            """SELECT w.id FROM workers w
               WHERE w.status='draining' AND NOT EXISTS (
                 SELECT 1 FROM task_attempts a
                 WHERE a.worker_id=w.id AND a.state IN ('reserved','leased','running')
               )"""
        ).fetchall()
        for worker in drained:
            conn.execute(
                """UPDATE workers SET status='revoked',revoked_at=?,updated_at=?
                   WHERE id=? AND status='draining'""",
                (stamp, stamp, worker["id"]),
            )
            conn.execute(
                """UPDATE sessions SET revoked_at=?
                   WHERE principal_type='worker' AND principal_id=? AND revoked_at IS NULL""",
                (stamp, worker["id"]),
            )
        return len(drained)

    def sweep_expired(self) -> dict[str, int]:
        """Expire stale reservations/leases and enqueue safe Broker work."""

        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            conn.execute(
                """UPDATE broker_commands SET state='expired'
                   WHERE state='pending' AND expires_at IS NOT NULL AND expires_at<=?""",
                (stamp,),
            )
            self._expire_reservations(conn, stamp)
            expired_leases = self._expire_leases(conn, stamp)
            expired_maintenance_jobs = self._expire_maintenance_jobs(conn, stamp)
            queued_commands = self._ensure_rekey_commands(conn, stamp)
        # Keep attacker-influenced authentication/replay tables bounded outside
        # the scheduling transaction. Expired maintenance leases above clear
        # their session foreign keys before this cleanup attempts deletion.
        self.db.prune_expired_security_state(stamp=stamp)
        return {
            "expired_leases": expired_leases,
            "expired_maintenance_jobs": expired_maintenance_jobs,
            "queued_broker_commands": queued_commands,
        }

    # ------------------------------------------------------------ authorization

    def require_user(self, user_id: str | None) -> sqlite3.Row:
        if not user_id:
            raise RepositoryError(FORBIDDEN, "ACCESS_DENIED", "A user principal is required.", 403)
        row = self.db.fetchone("SELECT * FROM users WHERE id=? AND status='active'", (user_id,))
        if row is None:
            raise RepositoryError(FORBIDDEN, "ACCESS_DENIED", "The user is not active.", 403)
        return row

    def membership(self, workspace_id: str, user_id: str | None) -> sqlite3.Row | None:
        if not user_id:
            return None
        return self.db.fetchone(
            """SELECT * FROM memberships
               WHERE workspace_id=? AND user_id=? AND status='active'""",
            (workspace_id, user_id),
        )

    def require_member(self, workspace_id: str, user_id: str | None) -> sqlite3.Row:
        row = self.membership(workspace_id, user_id)
        if row is None:
            raise RepositoryError(
                FORBIDDEN, "WORKSPACE_ACCESS_DENIED", "Workspace access denied.", 403
            )
        return row

    def require_admin(self, workspace_id: str, user_id: str | None) -> sqlite3.Row:
        row = self.require_member(workspace_id, user_id)
        if row["role"] not in ("owner", "admin"):
            raise RepositoryError(
                FORBIDDEN, "WORKSPACE_ADMIN_REQUIRED", "Workspace admin access is required.", 403
            )
        return row

    def require_owner(self, workspace_id: str, user_id: str | None) -> sqlite3.Row:
        """Require the single v0.3 Workspace root-of-trust principal."""

        row = self.require_member(workspace_id, user_id)
        if row["role"] != "owner":
            raise RepositoryError(
                FORBIDDEN,
                "WORKSPACE_OWNER_REQUIRED",
                "Workspace Owner access is required for encryption recipients.",
                403,
            )
        return row

    def require_service(self, workspace_id: str, service_id: str) -> sqlite3.Row:
        row = self.db.fetchone(
            """SELECT * FROM services
               WHERE id=? AND workspace_id=? AND status='active'""",
            (service_id, workspace_id),
        )
        if row is None:
            raise RepositoryError(
                FORBIDDEN,
                "SERVICE_WORKSPACE_ACCESS_DENIED",
                "Service Workspace access denied.",
                403,
            )
        return row

    def require_task_consumer(
        self,
        task: sqlite3.Row,
        *,
        principal_type: str,
        principal_id: str,
        user_id: str | None,
        allow_workspace_admin: bool = False,
    ) -> None:
        if principal_type == "service":
            self.require_service(task["workspace_id"], principal_id)
            allowed = (
                task["consumer_principal_type"] == "service"
                and task["consumer_principal_id"] == principal_id
            )
        else:
            membership = self.require_member(task["workspace_id"], user_id)
            allowed = task["consumer_user_id"] == user_id or (
                allow_workspace_admin and membership["role"] in ("owner", "admin")
            )
        if not allowed:
            raise RepositoryError(FORBIDDEN, "TASK_ACCESS_DENIED", "Task access denied.", 403)

    # ---------------------------------------------------------------- workspaces

    def create_workspace(
        self,
        *,
        user_id: str,
        name: str,
        founder_broker_id: str | None = None,
        enrollment_policy: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self.require_user(user_id)
        stamp = now()
        workspace_id = new_id("wsp")
        with self.db.transaction(immediate=True) as conn:
            if founder_broker_id:
                broker = conn.execute(
                    "SELECT * FROM brokers WHERE id=? AND owner_user_id=? AND status='active'",
                    (founder_broker_id, user_id),
                ).fetchone()
                if broker is None:
                    raise RepositoryError(
                        FORBIDDEN,
                        "BROKER_ACCESS_DENIED",
                        "Founder broker is not owned by the user.",
                        403,
                    )
            conn.execute(
                """INSERT INTO workspaces
                   (id,name,owner_user_id,founder_broker_id,enrollment_policy,status,created_at,updated_at)
                   VALUES (?,?,?,?,?,'active',?,?)""",
                (
                    workspace_id,
                    name,
                    user_id,
                    founder_broker_id,
                    json_text(enrollment_policy or {}),
                    stamp,
                    stamp,
                ),
            )
            conn.execute(
                """INSERT INTO memberships
                   (workspace_id,user_id,role,status,created_at) VALUES (?,?,'owner','active',?)""",
                (workspace_id, user_id, stamp),
            )
        return row_dict(
            self.db.fetchone("SELECT * FROM workspaces WHERE id=?", (workspace_id,)),
            json_columns={"enrollment_policy"},
        )

    def list_workspaces(self, user_id: str) -> list[dict[str, Any]]:
        self.require_user(user_id)
        return [
            row_dict(row, json_columns={"enrollment_policy"})
            for row in self.db.fetchall(
                """SELECT w.*,m.role FROM workspaces w
                   JOIN memberships m ON m.workspace_id=w.id
                   WHERE m.user_id=? AND m.status='active' AND w.status='active'
                   ORDER BY w.created_at""",
                (user_id,),
            )
        ]

    def create_pool(
        self, *, workspace_id: str, user_id: str, name: str, policy: dict[str, Any]
    ) -> dict[str, Any]:
        self.require_admin(workspace_id, user_id)
        pool_id = new_id("pol")
        stamp = now()
        try:
            self.db.execute(
                """INSERT INTO pools
                   (id,workspace_id,name,policy,status,created_at,updated_at)
                   VALUES (?,?,?,?,'active',?,?)""",
                (pool_id, workspace_id, name, json_text(policy), stamp, stamp),
            )
        except sqlite3.IntegrityError as exc:
            raise RepositoryError(
                VALIDATION_FAILED, "POOL_NAME_EXISTS", "A pool with this name already exists.", 409
            ) from exc
        return row_dict(
            self.db.fetchone("SELECT * FROM pools WHERE id=?", (pool_id,)), json_columns={"policy"}
        )

    def list_pools(self, *, workspace_id: str, user_id: str) -> list[dict[str, Any]]:
        self.require_member(workspace_id, user_id)
        return [
            row_dict(row, json_columns={"policy"})
            for row in self.db.fetchall(
                "SELECT * FROM pools WHERE workspace_id=? AND status='active' ORDER BY created_at",
                (workspace_id,),
            )
        ]

    def revoke_device(self, *, device_id: str, user_id: str) -> dict[str, Any]:
        device = self.db.fetchone(
            "SELECT * FROM devices WHERE id=? AND user_id=?", (device_id, user_id)
        )
        if device is None:
            raise RepositoryError(FORBIDDEN, "DEVICE_ACCESS_DENIED", "Device access denied.", 403)
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            conn.execute(
                "UPDATE devices SET status='revoked',revoked_at=? WHERE id=?", (stamp, device_id)
            )
            conn.execute(
                "UPDATE sessions SET revoked_at=? WHERE principal_type='device' AND principal_id=? AND revoked_at IS NULL",
                (stamp, device_id),
            )
            conn.execute(
                "UPDATE broker_devices SET status='revoked',revoked_at=? WHERE device_id=? AND status='active'",
                (stamp, device_id),
            )
            conn.execute(
                """UPDATE worker_maintenance_jobs
                   SET state='cancelled',completed_at=?,updated_at=?,lease_session_id=NULL,
                       lease_expires_at=NULL,fencing_token=fencing_token+1
                   WHERE issued_by_device_id=?
                     AND state IN ('awaiting_upload','queued','leased','running','restarting')""",
                (stamp, stamp, device_id),
            )
        return {"device_id": device_id, "status": "revoked", "revoked_at": stamp}

    def register_recovered_device(
        self,
        *,
        user_id: str,
        challenge_id: str,
        device_id: str,
        device_name: str,
        device_signing_public_key: str,
        device_encryption_public_key: str,
        device_certificate: dict[str, Any],
    ) -> dict[str, Any]:
        """Atomically consume a recovery challenge and activate a new device."""

        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            challenge = conn.execute(
                """SELECT * FROM device_recovery_challenges
                   WHERE id=? AND user_id=? AND device_id=?
                     AND consumed_at IS NULL AND expires_at>?""",
                (challenge_id, user_id, device_id, stamp),
            ).fetchone()
            if challenge is None:
                raise RepositoryError(
                    100004,
                    "CHALLENGE_INVALID_OR_EXPIRED",
                    "The device recovery challenge is invalid or expired.",
                    401,
                )
            if conn.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone():
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "DEVICE_ALREADY_EXISTS",
                    "The device already exists.",
                    409,
                )
            conn.execute(
                """INSERT INTO devices
                   (id,user_id,name,signing_public_key,encryption_public_key,certificate,status,created_at,last_seen_at)
                   VALUES (?,?,?,?,?,?,'active',?,?)""",
                (
                    device_id,
                    user_id,
                    device_name,
                    device_signing_public_key,
                    device_encryption_public_key,
                    json_text(device_certificate),
                    stamp,
                    stamp,
                ),
            )
            conn.execute(
                "UPDATE device_recovery_challenges SET consumed_at=? WHERE id=?",
                (stamp, challenge_id),
            )
        return row_dict(self.db.fetchone("SELECT * FROM devices WHERE id=?", (device_id,)))

    # ---------------------------------------------------------- Workspace keys

    @staticmethod
    def _workspace_admission_subject_id(workspace_id: str, user_id: str) -> str:
        return f"{workspace_id}:{user_id}"

    @staticmethod
    def _verified_workspace_admission(
        conn: sqlite3.Connection,
        *,
        workspace_id: str,
        subject_user_id: str,
    ) -> dict[str, Any]:
        """Load and re-verify the Owner-signed admission and identity chain."""

        owner = conn.execute(
            """SELECT u.* FROM memberships m JOIN users u ON u.id=m.user_id
               WHERE m.workspace_id=? AND m.role='owner' AND m.status='active'
                 AND u.status='active'""",
            (workspace_id,),
        ).fetchone()
        admission = conn.execute(
            """SELECT * FROM key_manifests
               WHERE subject_type='workspace_recipient_admission'
                 AND subject_id=? AND key_version=1 AND revoked_at IS NULL""",
            (GatewayRepository._workspace_admission_subject_id(workspace_id, subject_user_id),),
        ).fetchone()
        if owner is None or admission is None or admission["signer_user_id"] != owner["id"]:
            raise RepositoryError(
                KEY_RECIPIENT_NOT_FOUND,
                "RECIPIENT_ADMISSION_REQUIRED",
                "A verified Workspace Owner admission is required for this key recipient.",
                409,
            )
        try:
            manifest = json.loads(admission["manifest"])
            signed = {
                "manifest": manifest,
                "signer_key_id": manifest["owner_root_key_id"],
                "signature": admission["signature"],
            }
            valid = verify_workspace_recipient_admission(
                signed,
                str(owner["root_signing_public_key"]),
                workspace_id=workspace_id,
                owner_user_id=str(owner["id"]),
                subject_user_id=subject_user_id,
            )
            claim = manifest["registration_claim"]
            proof_signature = manifest["registration_proof_signature"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            valid = False
            signed = {}
            manifest = {}
            claim = {}
            proof_signature = ""
        subject_user = conn.execute(
            "SELECT * FROM users WHERE id=? AND status='active'", (subject_user_id,)
        ).fetchone()
        initial_device = conn.execute(
            """SELECT * FROM devices WHERE id=? AND user_id=?""",
            (claim.get("device_id"), subject_user_id),
        ).fetchone()
        database_binding_valid = bool(
            valid
            and subject_user is not None
            and initial_device is not None
            and subject_user["root_signing_public_key"] == claim.get("root_signing_public_key")
            and subject_user["root_encryption_public_key"]
            == claim.get("root_encryption_public_key")
            and initial_device["signing_public_key"] == claim.get("device_signing_public_key")
            and initial_device["encryption_public_key"]
            == claim.get("device_encryption_public_key")
            and canonical_json(json.loads(initial_device["certificate"]))
            == canonical_json(claim.get("device_certificate", {}))
        )
        enrollment_id = manifest.get("enrollment_id") if isinstance(manifest, dict) else None
        if database_binding_valid and enrollment_id is not None:
            enrollment = conn.execute(
                """SELECT * FROM enrollments
                   WHERE id=? AND workspace_id=? AND kind IN ('user','workspace_member')
                     AND subject_user_id=? AND subject_id=? AND state IN ('pending','active')""",
                (
                    enrollment_id,
                    workspace_id,
                    subject_user_id,
                    claim.get("device_id"),
                ),
            ).fetchone()
            try:
                enrollment_record = json.loads(enrollment["claim"] or "null")
                database_binding_valid = bool(
                    enrollment is not None
                    and canonical_json(enrollment_record)
                    == canonical_json(
                        {
                            "registration_claim": claim,
                            "proof_signature": proof_signature,
                        }
                    )
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                database_binding_valid = False
        elif database_binding_valid:
            database_binding_valid = bool(
                subject_user_id == owner["id"]
                and claim.get("invite_id") == f"workspace-owner-self:{workspace_id}"
            )
        if not database_binding_valid:
            raise RepositoryError(
                SIGNATURE_INVALID,
                "RECIPIENT_ADMISSION_INVALID",
                "The Workspace recipient admission identity chain is invalid.",
                409,
            )
        return {
            "signed_admission": signed,
            "admission_digest": workspace_recipient_admission_digest(signed),
            "owner_user_id": str(owner["id"]),
            "owner_root_signing_public_key": str(owner["root_signing_public_key"]),
            "claim": claim,
        }

    def put_workspace_recipient_admission(
        self,
        *,
        workspace_id: str,
        owner_user_id: str,
        enrollment_id: str | None,
        signed_admission: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist an immutable Owner-signed admission after code verification."""

        self.require_owner(workspace_id, owner_user_id)
        try:
            manifest = signed_admission["manifest"]
            subject_user_id = str(manifest["subject_user_id"])
            if manifest.get("enrollment_id") != enrollment_id:
                raise ValueError
        except (KeyError, TypeError, ValueError) as exc:
            raise RepositoryError(
                SIGNATURE_INVALID,
                "RECIPIENT_ADMISSION_INVALID",
                "The Workspace recipient admission is invalid.",
                422,
            ) from exc
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            owner = conn.execute(
                """SELECT u.* FROM memberships m JOIN users u ON u.id=m.user_id
                   WHERE m.workspace_id=? AND m.user_id=? AND m.role='owner'
                     AND m.status='active' AND u.status='active'""",
                (workspace_id, owner_user_id),
            ).fetchone()
            valid = bool(
                owner is not None
                and verify_workspace_recipient_admission(
                    signed_admission,
                    str(owner["root_signing_public_key"]),
                    workspace_id=workspace_id,
                    owner_user_id=owner_user_id,
                    subject_user_id=subject_user_id,
                    enrollment_id=enrollment_id,
                )
            )
            if not valid:
                raise RepositoryError(
                    SIGNATURE_INVALID,
                    "RECIPIENT_ADMISSION_INVALID",
                    "The Workspace recipient admission signature or binding is invalid.",
                    422,
                )
            if enrollment_id is None:
                valid_subject = bool(
                    subject_user_id == owner_user_id
                    and manifest.get("registration_claim", {}).get("invite_id")
                    == f"workspace-owner-self:{workspace_id}"
                )
            else:
                enrollment = conn.execute(
                    """SELECT * FROM enrollments
                       WHERE id=? AND workspace_id=? AND kind IN ('user','workspace_member')
                         AND subject_user_id=? AND subject_id=?
                         AND state IN ('pending','active')""",
                    (
                        enrollment_id,
                        workspace_id,
                        subject_user_id,
                        manifest.get("subject_device_id"),
                    ),
                ).fetchone()
                try:
                    record = json.loads(enrollment["claim"] or "null")
                    valid_subject = bool(
                        enrollment is not None
                        and canonical_json(record)
                        == canonical_json(
                            {
                                "registration_claim": manifest["registration_claim"],
                                "proof_signature": manifest["registration_proof_signature"],
                            }
                        )
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    valid_subject = False
            if not valid_subject:
                raise RepositoryError(
                    SIGNATURE_INVALID,
                    "RECIPIENT_ADMISSION_INVALID",
                    "The admission does not match its User enrollment.",
                    409,
                )
            subject = self._workspace_admission_subject_id(workspace_id, subject_user_id)
            existing = conn.execute(
                """SELECT * FROM key_manifests
                   WHERE subject_type='workspace_recipient_admission'
                     AND subject_id=? AND key_version=1 AND revoked_at IS NULL""",
                (subject,),
            ).fetchone()
            if existing is not None:
                stored = {
                    "manifest": json.loads(existing["manifest"]),
                    "signer_key_id": manifest["owner_root_key_id"],
                    "signature": existing["signature"],
                }
                stored_semantics = dict(stored["manifest"])
                presented_semantics = dict(manifest)
                stored_semantics.pop("issued_at", None)
                presented_semantics.pop("issued_at", None)
                if canonical_json(stored_semantics) != canonical_json(presented_semantics):
                    raise RepositoryError(
                        IDEMPOTENCY_CONFLICT,
                        "RECIPIENT_ADMISSION_CONFLICT",
                        "A different admission is already pinned for this Workspace User.",
                        409,
                    )
            else:
                conn.execute(
                    """INSERT INTO key_manifests
                       (id,subject_type,subject_id,key_version,manifest,signature,
                        signer_user_id,created_at)
                       VALUES (?,'workspace_recipient_admission',?,1,?,?,?,?)""",
                    (
                        new_id("kmf"),
                        subject,
                        json_text(manifest),
                        signed_admission["signature"],
                        owner_user_id,
                        stamp,
                    ),
                )
            # Re-read and validate against the User/Device database rows.
            bundle = self._verified_workspace_admission(
                conn,
                workspace_id=workspace_id,
                subject_user_id=subject_user_id,
            )
        return {
            "workspace_id": workspace_id,
            "subject_user_id": subject_user_id,
            "enrollment_id": enrollment_id,
            "admission_digest": bundle["admission_digest"],
            "signed_admission": bundle["signed_admission"],
        }

    def workspace_recipient_admission(
        self,
        *,
        workspace_id: str,
        owner_user_id: str,
        subject_user_id: str,
    ) -> dict[str, Any]:
        self.require_owner(workspace_id, owner_user_id)
        with self.db.transaction() as conn:
            bundle = self._verified_workspace_admission(
                conn,
                workspace_id=workspace_id,
                subject_user_id=subject_user_id,
            )
        return {
            "workspace_id": workspace_id,
            "subject_user_id": subject_user_id,
            "admission_digest": bundle["admission_digest"],
            "signed_admission": bundle["signed_admission"],
            "admission_signer_user_id": bundle["owner_user_id"],
            "admission_signer_root_signing_public_key": bundle[
                "owner_root_signing_public_key"
            ],
        }

    @staticmethod
    def _workspace_key_recipient_set(
        conn: sqlite3.Connection, workspace_id: str
    ) -> list[dict[str, Any]]:
        recipients: list[dict[str, Any]] = []
        # An active Service is not implicitly entitled to the Workspace Data
        # Key. Until Services have an equivalent Owner-signed admission, omit
        # them from new recipient snapshots instead of allowing their mere
        # registration to block safe User/Device key rotation. Direct Service
        # recipient lookup/grant remains fail-closed in workspace_key_recipient.
        members = conn.execute(
            """SELECT u.* FROM memberships m JOIN users u ON u.id=m.user_id
               WHERE m.workspace_id=? AND m.status='active' AND u.status='active'
               ORDER BY u.id""",
            (workspace_id,),
        ).fetchall()
        for user in members:
            user_id = str(user["id"])
            admission = GatewayRepository._verified_workspace_admission(
                conn,
                workspace_id=workspace_id,
                subject_user_id=user_id,
            )
            root_key = str(user["root_encryption_public_key"])
            root_key_digest = hashlib.sha256(
                b64url_decode(root_key, expected_length=32)
            ).hexdigest()
            root_binding = {
                "recipient_type": "user_recovery",
                "recipient_id": user_id,
                "subject_user_id": user_id,
                "encryption_public_key": root_key,
                "recipient_key_sha256": root_key_digest,
                "admission_digest": admission["admission_digest"],
            }
            recipients.append(
                {
                    **root_binding,
                    "recipient_binding_digest": hashlib.sha256(
                        canonical_json(root_binding)
                    ).hexdigest(),
                    "signed_admission": admission["signed_admission"],
                    "admission_signer_user_id": admission["owner_user_id"],
                    "admission_signer_root_signing_public_key": admission[
                        "owner_root_signing_public_key"
                    ],
                }
            )
            root_signing = b64url_decode(
                str(admission["claim"]["root_signing_public_key"]), expected_length=32
            )
            for device in conn.execute(
                """SELECT * FROM devices
                   WHERE user_id=? AND status='active' ORDER BY id""",
                (user_id,),
            ).fetchall():
                try:
                    certificate = json.loads(device["certificate"])
                    certificate_payload = certificate["payload"]
                    device_chain_valid = bool(
                        verify_device_certificate(certificate, root_signing)
                        and certificate_payload.get("device_id") == device["id"]
                        and certificate_payload.get("signing_public_key")
                        == device["signing_public_key"]
                        and certificate_payload.get("encryption_public_key")
                        == device["encryption_public_key"]
                    )
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    device_chain_valid = False
                    certificate = {}
                if not device_chain_valid:
                    raise RepositoryError(
                        SIGNATURE_INVALID,
                        "DEVICE_RECIPIENT_CERTIFICATE_INVALID",
                        "A Device recipient certificate does not chain to its admitted User root.",
                        409,
                    )
                device_key = str(device["encryption_public_key"])
                device_key_digest = hashlib.sha256(
                    b64url_decode(device_key, expected_length=32)
                ).hexdigest()
                device_binding = {
                    "recipient_type": "device",
                    "recipient_id": str(device["id"]),
                    "subject_user_id": user_id,
                    "encryption_public_key": device_key,
                    "recipient_key_sha256": device_key_digest,
                    "admission_digest": admission["admission_digest"],
                    "device_certificate_sha256": hashlib.sha256(
                        canonical_json(certificate)
                    ).hexdigest(),
                }
                recipients.append(
                    {
                        **device_binding,
                        "recipient_binding_digest": hashlib.sha256(
                            canonical_json(device_binding)
                        ).hexdigest(),
                        "device_certificate": certificate,
                        "signed_admission": admission["signed_admission"],
                        "admission_signer_user_id": admission["owner_user_id"],
                        "admission_signer_root_signing_public_key": admission[
                            "owner_root_signing_public_key"
                        ],
                    }
                )
        recipients.sort(key=lambda value: (value["recipient_type"], value["recipient_id"]))
        return recipients

    @staticmethod
    def _workspace_key_recipient_digest(recipients: list[dict[str, Any]]) -> str:
        return hashlib.sha256(canonical_json(recipients)).hexdigest()

    def workspace_key_rotation_recipients(
        self, *, workspace_id: str, user_id: str
    ) -> dict[str, Any]:
        self.require_owner(workspace_id, user_id)
        with self.db.transaction() as conn:
            workspace = conn.execute(
                "SELECT key_version FROM workspaces WHERE id=? AND status='active'", (workspace_id,)
            ).fetchone()
            if workspace is None:
                raise RepositoryError(
                    WORKSPACE_NOT_FOUND, "WORKSPACE_NOT_FOUND", "Workspace not found.", 404
                )
            recipients = self._workspace_key_recipient_set(conn, workspace_id)
        return {
            "workspace_id": workspace_id,
            "current_key_version": int(workspace["key_version"]),
            "next_key_version": int(workspace["key_version"]) + 1,
            "recipient_set_digest": self._workspace_key_recipient_digest(recipients),
            "recipients": recipients,
        }

    @staticmethod
    def _stored_rotation_matches(
        conn: sqlite3.Connection,
        *,
        workspace_id: str,
        key_version: int,
        user_id: str,
        grants: dict[tuple[str, str], dict[str, Any]],
    ) -> bool:
        rows = conn.execute(
            """SELECT e.recipient_type,e.recipient_id,e.algorithm,e.envelope,
                      m.manifest,m.signature,m.signer_user_id
               FROM key_envelopes e JOIN key_manifests m
                 ON m.subject_type='workspace_key_envelope'
                AND m.subject_id=(e.workspace_id || ':' || e.recipient_type || ':' || e.recipient_id)
                AND m.key_version=e.key_version AND m.revoked_at IS NULL
               WHERE e.workspace_id=? AND e.task_id IS NULL AND e.key_version=?
                 AND e.revoked_at IS NULL""",
            (workspace_id, key_version),
        ).fetchall()
        if len(rows) != len(grants):
            return False
        for row in rows:
            grant = grants.get((str(row["recipient_type"]), str(row["recipient_id"])))
            if grant is None:
                return False
            signed = grant["signed_manifest"]
            if (
                str(row["algorithm"]) != grant["algorithm"]
                or json.loads(row["envelope"]) != grant["envelope"]
                or json.loads(row["manifest"]) != signed["manifest"]
                or str(row["signature"]) != signed["signature"]
                or str(row["signer_user_id"]) != user_id
            ):
                return False
        return True

    def rotate_workspace_key(
        self,
        *,
        workspace_id: str,
        user_id: str,
        rotation_id: str,
        expected_key_version: int,
        new_key_version: int,
        recipient_set_digest: str,
        envelopes: list[dict[str, Any]],
    ) -> dict[str, Any]:
        self.require_owner(workspace_id, user_id)
        if new_key_version != expected_key_version + 1:
            raise RepositoryError(
                400002,
                "KEY_VERSION_UNAVAILABLE",
                "Workspace key rotations must advance exactly one version.",
                409,
            )
        grants: dict[tuple[str, str], dict[str, Any]] = {}
        for grant in envelopes:
            pair = (str(grant["recipient_type"]), str(grant["recipient_id"]))
            if pair in grants or int(grant["key_version"]) != new_key_version:
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "VALIDATION_FAILED",
                    "Workspace key rotation envelope set is invalid.",
                    422,
                )
            grants[pair] = grant

        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            admin = conn.execute(
                """SELECT role FROM memberships WHERE workspace_id=? AND user_id=?
                   AND status='active' AND role='owner'""",
                (workspace_id, user_id),
            ).fetchone()
            workspace = conn.execute(
                "SELECT key_version FROM workspaces WHERE id=? AND status='active'", (workspace_id,)
            ).fetchone()
            if admin is None:
                raise RepositoryError(
                    FORBIDDEN,
                    "WORKSPACE_OWNER_REQUIRED",
                    "Workspace Owner access is required for key rotation.",
                    403,
                )
            if workspace is None:
                raise RepositoryError(
                    WORKSPACE_NOT_FOUND, "WORKSPACE_NOT_FOUND", "Workspace not found.", 404
                )

            recipients = self._workspace_key_recipient_set(conn, workspace_id)
            current_digest = self._workspace_key_recipient_digest(recipients)
            expected_pairs = {
                (value["recipient_type"], value["recipient_id"]) for value in recipients
            }
            if current_digest != recipient_set_digest or set(grants) != expected_pairs:
                raise RepositoryError(
                    400002,
                    "KEY_VERSION_UNAVAILABLE",
                    "Workspace key recipients changed; fetch a new rotation snapshot.",
                    409,
                )

            current_version = int(workspace["key_version"])
            if current_version == new_key_version and self._stored_rotation_matches(
                conn,
                workspace_id=workspace_id,
                key_version=new_key_version,
                user_id=user_id,
                grants=grants,
            ):
                return {
                    "workspace_id": workspace_id,
                    "rotation_id": rotation_id,
                    "previous_key_version": expected_key_version,
                    "key_version": new_key_version,
                    "recipient_count": len(recipients),
                    "old_envelopes_retained": True,
                    "idempotent_replay": True,
                }
            if current_version != expected_key_version:
                raise RepositoryError(
                    400002,
                    "KEY_VERSION_UNAVAILABLE",
                    "The Workspace key version changed during rotation.",
                    409,
                )

            existing = conn.execute(
                """SELECT 1 FROM key_envelopes WHERE workspace_id=? AND task_id IS NULL
                   AND key_version=? LIMIT 1""",
                (workspace_id, new_key_version),
            ).fetchone()
            if existing is not None:
                raise RepositoryError(
                    400002,
                    "KEY_VERSION_UNAVAILABLE",
                    "The target Workspace key version already contains envelopes.",
                    409,
                )

            for recipient in recipients:
                recipient_type = recipient["recipient_type"]
                recipient_id = recipient["recipient_id"]
                grant = grants[(recipient_type, recipient_id)]
                signed = grant["signed_manifest"]
                conn.execute(
                    """INSERT INTO key_envelopes
                       (id,workspace_id,task_id,recipient_type,recipient_id,key_version,
                        algorithm,envelope,created_at)
                       VALUES (?,?,NULL,?,?,?,?,?,?)""",
                    (
                        new_id("ken"),
                        workspace_id,
                        recipient_type,
                        recipient_id,
                        new_key_version,
                        grant["algorithm"],
                        json_text(grant["envelope"]),
                        stamp,
                    ),
                )
                conn.execute(
                    """INSERT INTO key_manifests
                       (id,subject_type,subject_id,key_version,manifest,signature,
                        signer_user_id,created_at)
                       VALUES (?, 'workspace_key_envelope',?,?,?,?,?,?)""",
                    (
                        new_id("kmf"),
                        f"{workspace_id}:{recipient_type}:{recipient_id}",
                        new_key_version,
                        json_text(signed["manifest"]),
                        signed["signature"],
                        user_id,
                        stamp,
                    ),
                )
            updated = conn.execute(
                """UPDATE workspaces SET key_version=?,updated_at=?
                   WHERE id=? AND key_version=? AND status='active'""",
                (new_key_version, stamp, workspace_id, expected_key_version),
            )
            if updated.rowcount != 1:
                raise RepositoryError(
                    400002,
                    "KEY_VERSION_UNAVAILABLE",
                    "The Workspace key version changed during rotation.",
                    409,
                )
            conn.execute(
                """INSERT INTO audit_events
                   (id,actor_type,actor_id,workspace_id,action,subject_type,subject_id,
                    safe_details,created_at)
                   VALUES (?, 'user',?,?,'workspace.key_rotated','workspace',?,?,?)""",
                (
                    new_id("aud"),
                    user_id,
                    workspace_id,
                    workspace_id,
                    json_text(
                        {
                            "rotation_id": rotation_id,
                            "previous_key_version": expected_key_version,
                            "key_version": new_key_version,
                            "recipient_count": len(recipients),
                        }
                    ),
                    stamp,
                ),
            )

        return {
            "workspace_id": workspace_id,
            "rotation_id": rotation_id,
            "previous_key_version": expected_key_version,
            "key_version": new_key_version,
            "recipient_count": len(recipients),
            "old_envelopes_retained": True,
            "idempotent_replay": False,
        }

    def workspace_key_recipient(
        self,
        *,
        workspace_id: str,
        user_id: str,
        recipient_type: str,
        recipient_id: str,
    ) -> dict[str, Any]:
        self.require_owner(workspace_id, user_id)
        if recipient_type == "service":
            raise RepositoryError(
                KEY_RECIPIENT_NOT_FOUND,
                "SERVICE_RECIPIENT_ADMISSION_UNSUPPORTED",
                "Service WDK recipients require a future verifiable admission protocol.",
                409,
            )
        with self.db.transaction() as conn:
            recipients = self._workspace_key_recipient_set(conn, workspace_id)
            recipient = next(
                (
                    item
                    for item in recipients
                    if item["recipient_type"] == recipient_type
                    and item["recipient_id"] == recipient_id
                ),
                None,
            )
            workspace = conn.execute(
                "SELECT key_version FROM workspaces WHERE id=? AND status='active'",
                (workspace_id,),
            ).fetchone()
        if recipient is None or workspace is None:
            raise RepositoryError(
                KEY_RECIPIENT_NOT_FOUND, "KEY_RECIPIENT_NOT_FOUND", "Key recipient not found.", 404
            )
        return {
            **recipient,
            "workspace_id": workspace_id,
            "key_version": int(workspace["key_version"]),
        }

    def grant_workspace_key(
        self,
        *,
        workspace_id: str,
        user_id: str,
        recipient_type: str,
        recipient_id: str,
        key_version: int,
        algorithm: str,
        envelope: dict[str, str],
        signed_manifest: dict[str, Any],
    ) -> dict[str, Any]:
        recipient = self.workspace_key_recipient(
            workspace_id=workspace_id,
            user_id=user_id,
            recipient_type=recipient_type,
            recipient_id=recipient_id,
        )
        if key_version != recipient["key_version"]:
            raise RepositoryError(
                400002,
                "KEY_VERSION_UNAVAILABLE",
                "The Workspace key version is not current.",
                409,
            )
        manifest = signed_manifest.get("manifest")
        if not isinstance(manifest, dict) or (
            manifest.get("recipient_public_key_sha256") != recipient["recipient_key_sha256"]
            or manifest.get("recipient_admission_sha256") != recipient["admission_digest"]
            or manifest.get("recipient_binding_digest")
            != recipient["recipient_binding_digest"]
        ):
            raise RepositoryError(
                SIGNATURE_INVALID,
                "KEY_RECIPIENT_BINDING_INVALID",
                "The key envelope is not bound to the verified recipient admission.",
                422,
            )
        stamp = now()
        envelope_id = new_id("ken")
        subject_id = f"{workspace_id}:{recipient_type}:{recipient_id}"
        with self.db.transaction(immediate=True) as conn:
            current = next(
                (
                    item
                    for item in self._workspace_key_recipient_set(conn, workspace_id)
                    if item["recipient_type"] == recipient_type
                    and item["recipient_id"] == recipient_id
                ),
                None,
            )
            if current is None or any(
                current[field] != recipient[field]
                for field in (
                    "encryption_public_key",
                    "recipient_key_sha256",
                    "admission_digest",
                    "recipient_binding_digest",
                )
            ):
                raise RepositoryError(
                    400002,
                    "KEY_RECIPIENT_CHANGED",
                    "The verified key recipient changed before the envelope was stored.",
                    409,
                )
            conn.execute(
                """UPDATE key_envelopes SET revoked_at=?
                   WHERE workspace_id=? AND task_id IS NULL AND recipient_type=?
                     AND recipient_id=? AND key_version=? AND revoked_at IS NULL""",
                (stamp, workspace_id, recipient_type, recipient_id, key_version),
            )
            conn.execute(
                """INSERT INTO key_envelopes
                   (id,workspace_id,task_id,recipient_type,recipient_id,key_version,algorithm,envelope,created_at)
                   VALUES (?,?,NULL,?,?,?,?,?,?)""",
                (
                    envelope_id,
                    workspace_id,
                    recipient_type,
                    recipient_id,
                    key_version,
                    algorithm,
                    json_text(envelope),
                    stamp,
                ),
            )
            conn.execute(
                """INSERT INTO key_manifests
                   (id,subject_type,subject_id,key_version,manifest,signature,signer_user_id,created_at)
                   VALUES (?, 'workspace_key_envelope',?,?,?,?,?,?)
                   ON CONFLICT(subject_type,subject_id,key_version) DO UPDATE SET
                     manifest=excluded.manifest,signature=excluded.signature,
                     signer_user_id=excluded.signer_user_id,created_at=excluded.created_at,
                     revoked_at=NULL""",
                (
                    new_id("kmf"),
                    subject_id,
                    key_version,
                    json_text(signed_manifest["manifest"]),
                    signed_manifest["signature"],
                    user_id,
                    stamp,
                ),
            )
        return {
            "id": envelope_id,
            "workspace_id": workspace_id,
            "recipient_type": recipient_type,
            "recipient_id": recipient_id,
            "key_version": key_version,
            "algorithm": algorithm,
            "created_at": stamp,
        }

    def workspace_key_envelopes(
        self,
        *,
        workspace_id: str,
        principal_type: str,
        principal_id: str,
        user_id: str | None,
        recipient_type: str,
        recipient_id: str,
        key_version: int | None,
    ) -> list[dict[str, Any]]:
        if principal_type == "service":
            service = self.db.fetchone(
                "SELECT * FROM services WHERE id=? AND workspace_id=? AND status='active'",
                (principal_id, workspace_id),
            )
            if service is None or recipient_type != "service" or recipient_id != principal_id:
                raise RepositoryError(
                    FORBIDDEN, "KEY_ENVELOPE_ACCESS_DENIED", "Key envelope access denied.", 403
                )
        else:
            self.require_member(workspace_id, user_id)
            if recipient_type == "user_recovery":
                allowed = recipient_id == user_id
            elif recipient_type == "device":
                device = self.db.fetchone(
                    "SELECT user_id FROM devices WHERE id=? AND status='active'", (recipient_id,)
                )
                allowed = bool(
                    device and device["user_id"] == user_id and recipient_id == principal_id
                )
            else:
                allowed = False
            if not allowed:
                raise RepositoryError(
                    FORBIDDEN, "KEY_ENVELOPE_ACCESS_DENIED", "Key envelope access denied.", 403
                )
        sql = """SELECT e.*,m.manifest,m.signature,m.signer_user_id,
                        u.root_signing_public_key AS signer_root_signing_public_key,
                        sm.role AS signer_workspace_role
                 FROM key_envelopes e LEFT JOIN key_manifests m
                   ON m.subject_type='workspace_key_envelope'
                  AND m.subject_id=(e.workspace_id || ':' || e.recipient_type || ':' || e.recipient_id)
                  AND m.key_version=e.key_version AND m.revoked_at IS NULL
                 LEFT JOIN users u ON u.id=m.signer_user_id AND u.status='active'
                 LEFT JOIN memberships sm ON sm.workspace_id=e.workspace_id
                   AND sm.user_id=m.signer_user_id AND sm.status='active'
                 WHERE e.workspace_id=? AND e.task_id IS NULL
                   AND e.recipient_type=? AND e.recipient_id=? AND e.revoked_at IS NULL"""
        args: list[Any] = [workspace_id, recipient_type, recipient_id]
        if key_version is not None:
            sql += " AND e.key_version=?"
            args.append(key_version)
        sql += " ORDER BY e.key_version DESC,e.created_at DESC"
        values: list[dict[str, Any]] = []
        for row in self.db.fetchall(sql, tuple(args)):
            value = row_dict(row, json_columns={"envelope", "manifest"})
            manifest = value.pop("manifest", None)
            signature = value.pop("signature", None)
            value["signed_manifest"] = (
                {
                    "manifest": manifest,
                    "signature": signature,
                    "signer_key_id": manifest.get("signer_root_key_id"),
                }
                if manifest is not None and signature is not None
                else None
            )
            values.append(value)
        return values

    # ------------------------------------------------------------------- brokers

    def create_broker(self, *, owner_user_id: str, name: str) -> dict[str, Any]:
        self.require_user(owner_user_id)
        broker_id = new_id("brk")
        stamp = now()
        self.db.execute(
            """INSERT INTO brokers(id,owner_user_id,name,status,created_at,updated_at)
               VALUES (?,?,?,'active',?,?)""",
            (broker_id, owner_user_id, name, stamp, stamp),
        )
        return row_dict(self.db.fetchone("SELECT * FROM brokers WHERE id=?", (broker_id,)))

    def list_brokers(self, *, owner_user_id: str) -> list[dict[str, Any]]:
        self.require_user(owner_user_id)
        values: list[dict[str, Any]] = []
        for row in self.db.fetchall(
            "SELECT * FROM brokers WHERE owner_user_id=? AND status='active' ORDER BY created_at",
            (owner_user_id,),
        ):
            value = row_dict(row)
            value["devices"] = [
                row_dict(device)
                for device in self.db.fetchall(
                    """SELECT bd.*,d.name,d.last_seen_at FROM broker_devices bd
                       JOIN devices d ON d.id=bd.device_id WHERE bd.broker_id=? ORDER BY bd.created_at""",
                    (row["id"],),
                )
            ]
            values.append(value)
        return values

    def attach_broker_device(
        self, *, broker_id: str, device_id: str, owner_user_id: str
    ) -> dict[str, Any]:
        broker = self.db.fetchone(
            "SELECT * FROM brokers WHERE id=? AND owner_user_id=? AND status='active'",
            (broker_id, owner_user_id),
        )
        device = self.db.fetchone(
            "SELECT * FROM devices WHERE id=? AND user_id=? AND status='active'",
            (device_id, owner_user_id),
        )
        if broker is None or device is None:
            raise RepositoryError(
                FORBIDDEN, "BROKER_ACCESS_DENIED", "Broker or device access denied.", 403
            )
        broker_device_id = new_id("bdev")
        try:
            self.db.execute(
                """INSERT INTO broker_devices
                   (id,broker_id,device_id,status,approved_by_user_id,created_at)
                   VALUES (?,?,?,'active',?,?)""",
                (broker_device_id, broker_id, device_id, owner_user_id, now()),
            )
        except sqlite3.IntegrityError:
            row = self.db.fetchone(
                "SELECT * FROM broker_devices WHERE broker_id=? AND device_id=?",
                (broker_id, device_id),
            )
            return row_dict(row)
        return row_dict(
            self.db.fetchone("SELECT * FROM broker_devices WHERE id=?", (broker_device_id,))
        )

    def broker_device_heartbeat(
        self,
        *,
        broker_device_id: str,
        user_id: str,
        broker_id: str,
        runtime_version: str | None,
        protocol_version: str,
        build_commit: str | None,
        journal_pending: int,
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute(
                """SELECT bd.*,b.owner_user_id FROM broker_devices bd
                   JOIN brokers b ON b.id=bd.broker_id WHERE bd.id=? OR bd.device_id=?""",
                (broker_device_id, broker_device_id),
            ).fetchone()
            if (
                row is None
                or row["owner_user_id"] != user_id
                or row["status"] != "active"
                or row["broker_id"] != broker_id
            ):
                raise RepositoryError(
                    FORBIDDEN,
                    "BROKER_DEVICE_ACCESS_DENIED",
                    "Broker device access denied.",
                    403,
                )
            conn.execute("UPDATE devices SET last_seen_at=? WHERE id=?", (stamp, row["device_id"]))
            conn.execute(
                """UPDATE broker_devices
                   SET runtime_version=?,protocol_version=?,build_commit=?,journal_pending=?,
                       heartbeat_at=? WHERE id=?""",
                (
                    runtime_version,
                    protocol_version,
                    build_commit,
                    journal_pending,
                    stamp,
                    row["id"],
                ),
            )
            self._expire_leases(conn, stamp)
            self._ensure_rekey_commands(conn, stamp, consumer_user_id=row["owner_user_id"])
        return {
            "ok": True,
            "broker_device_id": broker_device_id,
            "last_seen_at": stamp,
            "runtime_version": runtime_version,
        }

    def broker_commands(
        self, *, broker_device_id: str, user_id: str, after: str
    ) -> list[dict[str, Any]]:
        row = self.db.fetchone(
            """SELECT bd.*,b.owner_user_id FROM broker_devices bd
               JOIN brokers b ON b.id=bd.broker_id WHERE bd.id=? OR bd.device_id=?""",
            (broker_device_id, broker_device_id),
        )
        if row is None or row["owner_user_id"] != user_id or row["status"] != "active":
            raise RepositoryError(
                FORBIDDEN, "BROKER_DEVICE_ACCESS_DENIED", "Broker device access denied.", 403
            )
        # Pending/completed state is the durable cursor.  Do not filter by a
        # timestamp: several commands can be enqueued in the same transaction,
        # and a restart between them must not hide an equal-timestamp command.
        return [
            row_dict(command, json_columns={"payload", "result"})
            for command in self.db.fetchall(
                """SELECT * FROM broker_commands
                   WHERE broker_device_id=? AND state='pending'
                     AND (expires_at IS NULL OR expires_at>?) ORDER BY created_at LIMIT 100""",
                (row["id"], now()),
            )
        ]

    def complete_broker_command(
        self,
        *,
        broker_device_id: str,
        command_id: str,
        user_id: str,
        succeeded: bool,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        self.broker_commands(broker_device_id=broker_device_id, user_id=user_id, after="")
        broker_device = self.db.fetchone(
            "SELECT id FROM broker_devices WHERE id=? OR device_id=?",
            (broker_device_id, broker_device_id),
        )
        command = self.db.fetchone(
            "SELECT command_type,payload FROM broker_commands WHERE id=? AND broker_device_id=?",
            (command_id, broker_device["id"]),
        )
        if command is None:
            raise RepositoryError(
                int(ErrorCode.BROKER_COMMAND_NOT_FOUND),
                "BROKER_COMMAND_NOT_FOUND",
                "Broker command not found or already completed.",
                404,
            )
        if command["command_type"] == "task_rekey":
            allowed_result_fields = {
                "status",
                "task_id",
                "attempt_id",
                "worker_id",
                "task_state",
            }
            command_payload = json.loads(command["payload"])
            status = result.get("status")
            task_id = result.get("task_id")
            task_state = result.get("task_state")
            allowed_task_states = {
                "committed",
                "queued",
                "reserved",
                "running",
                "succeeded",
                "cancelled",
            }
            invalid_result = (
                bool(set(result) - allowed_result_fields)
                or status not in {"rekeyed", "not_needed"}
                or task_id != command_payload.get("task_id")
                or task_state not in allowed_task_states
            )
            if status == "rekeyed":
                attempt = self.db.fetchone(
                    """SELECT worker_id FROM task_attempts
                       WHERE id=? AND task_id=?""",
                    (result.get("attempt_id"), task_id),
                )
                invalid_result = invalid_result or (
                    task_state != "committed"
                    or attempt is None
                    or result.get("worker_id") != attempt["worker_id"]
                )
            else:
                invalid_result = invalid_result or any(
                    field in result for field in ("attempt_id", "worker_id")
                )
            if invalid_result:
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "BROKER_COMMAND_RESULT_INVALID",
                    "Broker rekey result contains unsupported fields.",
                    422,
                )
        stamp = now()
        cursor = self.db.execute(
            """UPDATE broker_commands SET state=?,result=?,completed_at=?
               WHERE id=? AND broker_device_id=? AND state='pending'""",
            (
                "completed" if succeeded else "failed",
                json_text(result),
                stamp,
                command_id,
                broker_device["id"],
            ),
        )
        if cursor.rowcount != 1:
            raise RepositoryError(
                int(ErrorCode.BROKER_COMMAND_NOT_FOUND),
                "BROKER_COMMAND_NOT_FOUND",
                "Broker command not found or already completed.",
                404,
            )
        return row_dict(
            self.db.fetchone("SELECT * FROM broker_commands WHERE id=?", (command_id,)),
            json_columns={"payload", "result"},
        )

    # --------------------------------------------------------------- enrollments

    def create_invite(
        self,
        *,
        issuer_user_id: str,
        workspace_id: str | None,
        pool_id: str | None,
        kind: str,
        method: str,
        scopes: list[str],
        relationship: str | None,
        subject_key_fingerprint: str | None,
        ttl_seconds: int,
    ) -> tuple[dict[str, Any], str]:
        if workspace_id and kind in {"user", "workspace_member", "service"}:
            # These principals can become WDK recipients.  Until a delegated
            # Workspace-admin PKI exists, only the pinned Owner root may issue
            # the Invite which establishes the recipient trust chain.
            self.require_owner(workspace_id, issuer_user_id)
        elif workspace_id:
            self.require_admin(workspace_id, issuer_user_id)
        else:
            self.require_user(issuer_user_id)
        if method not in ("direct_invite", "invite_approval"):
            raise RepositoryError(
                VALIDATION_FAILED,
                "INVALID_ENROLLMENT_METHOD",
                "Invite method must be direct_invite or invite_approval.",
                422,
            )
        if kind == "worker_allocation":
            raise RepositoryError(
                int(ErrorCode.ENROLLMENT_CLOSED),
                "ENROLLMENT_CLOSED",
                "Worker allocation uses owner offer and signed Workspace approval, not Invite claim.",
                403,
                details={"reason": "worker_allocation_requires_offer"},
            )
        if kind not in {"user", "broker_device", "service", "workspace_member"}:
            raise RepositoryError(
                VALIDATION_FAILED,
                "INVALID_ENROLLMENT_KIND",
                "Unsupported Invite kind.",
                422,
            )
        if kind == "service":
            requested = set(scopes)
            if not requested or not requested <= SERVICE_SCOPES:
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "INVALID_SERVICE_SCOPES",
                    "A Service invite requires one or more supported least-privilege scopes.",
                    422,
                    details={"allowed_scopes": sorted(SERVICE_SCOPES)},
                )
        elif scopes:
            raise RepositoryError(
                VALIDATION_FAILED,
                "SCOPES_NOT_ALLOWED",
                "Only a Service invite may grant scopes.",
                422,
            )
        if kind in {"user", "workspace_member"}:
            if relationship not in (None, "admin", "member"):
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "INVALID_MEMBERSHIP_RELATIONSHIP",
                    "Membership relationship must be admin or member.",
                    422,
                )
        elif relationship is not None:
            raise RepositoryError(
                VALIDATION_FAILED,
                "RELATIONSHIP_NOT_ALLOWED",
                "This Invite kind does not accept a relationship.",
                422,
            )
        if pool_id:
            pool = self.db.fetchone(
                "SELECT * FROM pools WHERE id=? AND workspace_id=?", (pool_id, workspace_id)
            )
            if pool is None:
                raise RepositoryError(POOL_NOT_FOUND, "POOL_NOT_FOUND", "Pool not found.", 404)
        invite_id = new_id("inv")
        secret = secrets.token_urlsafe(32)
        stamp = now()
        self.db.execute(
            """INSERT INTO enrollments
               (id,kind,method,state,workspace_id,pool_id,issuer_user_id,subject_key_fingerprint,
                scopes,relationship,invite_secret_hash,expires_at,created_at,updated_at)
               VALUES (?,?,?,'issued',?,?,?,?,?,?,?,?,?,?)""",
            (
                invite_id,
                kind,
                method,
                workspace_id,
                pool_id,
                issuer_user_id,
                subject_key_fingerprint,
                json_text(scopes),
                relationship,
                hashlib.sha256(secret.encode()).hexdigest(),
                stamp + ttl_seconds,
                stamp,
                stamp,
            ),
        )
        return self.enrollment(invite_id), secret

    def enrollment(self, enrollment_id: str) -> dict[str, Any]:
        row = self.db.fetchone("SELECT * FROM enrollments WHERE id=?", (enrollment_id,))
        if row is None:
            raise RepositoryError(
                ENROLLMENT_NOT_FOUND, "ENROLLMENT_NOT_FOUND", "Enrollment not found.", 404
            )
        value = row_dict(row, json_columns={"scopes", "claim"})
        if row["kind"] in {"user", "workspace_member"}:
            record = value.get("claim")
            if isinstance(record, dict) and isinstance(record.get("registration_claim"), dict):
                value["claim"] = record["registration_claim"]
                value["proof_signature"] = record.get("proof_signature")
        # Secret verifiers are storage-only material.  They are never needed by
        # an administrator or claimant and must not become API/audit output.
        value.pop("invite_secret_hash", None)
        return value

    @staticmethod
    def _worker_enrollment_record(row: sqlite3.Row) -> dict[str, Any]:
        try:
            value = json.loads(row["claim"] or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise RepositoryError(
                VALIDATION_FAILED,
                "WORKER_ENROLLMENT_RECORD_INVALID",
                "The Worker enrollment record is invalid.",
                409,
            ) from exc
        if not isinstance(value, dict) or not isinstance(value.get("config"), dict):
            raise RepositoryError(
                VALIDATION_FAILED,
                "WORKER_ENROLLMENT_RECORD_INVALID",
                "The Worker enrollment record is invalid.",
                409,
            )
        return value

    @staticmethod
    def _verify_worker_enrollment_claim(
        claim: dict[str, Any], proof_signature: str
    ) -> tuple[bytes, bytes]:
        """Verify the exact public claim and possession of its signing key."""

        try:
            signing_key = b64url_decode(str(claim["signing_public_key"]), expected_length=32)
            encryption_key = b64url_decode(
                str(claim["encryption_public_key"]), expected_length=32
            )
            signature = b64url_decode(proof_signature, expected_length=64)
            shape_is_valid = (
                set(claim)
                == {
                    "version",
                    "kind",
                    "invite_id",
                    "worker_key_id",
                    "name",
                    "signing_public_key",
                    "encryption_public_key",
                    "executor_type",
                    "executor_version",
                    "capabilities",
                    "capacity",
                }
                and claim["version"] == 1
                and claim["kind"] == "vgen-worker-enrollment-claim"
                and claim["worker_key_id"] == device_key_id(signing_key)
                and isinstance(claim["invite_id"], str)
                and bool(claim["invite_id"])
                and isinstance(claim["name"], str)
                and bool(claim["name"].strip())
                and isinstance(claim["executor_type"], str)
                and bool(claim["executor_type"].strip())
                and isinstance(claim["executor_version"], str)
                and isinstance(claim["capabilities"], dict)
                and isinstance(claim["capacity"], int)
                and not isinstance(claim["capacity"], bool)
                and 1 <= claim["capacity"] <= 64
            )
            signature_is_valid = shape_is_valid and verify_message(
                signing_key,
                canonical_json(claim),
                signature,
                context=_WORKER_ENROLLMENT_CONTEXT,
            )
        except (KeyError, TypeError, ValueError):
            signature_is_valid = False
            signing_key = b""
            encryption_key = b""
        if not signature_is_valid:
            raise RepositoryError(
                SIGNATURE_INVALID,
                "SIGNATURE_INVALID",
                "The Worker enrollment proof is invalid.",
                401,
            )
        return signing_key, encryption_key

    def _worker_enrollment_value(
        self,
        row: sqlite3.Row,
        *,
        include_claim: bool,
    ) -> dict[str, Any]:
        """Return a role-limited view which never exposes the Invite secret hash."""

        record = self._worker_enrollment_record(row)
        config = record["config"]
        worker_claim = record.get("worker_claim")
        enrollment = {
            "id": row["id"],
            "kind": row["kind"],
            "method": row["method"],
            "state": row["state"],
            "workspace_id": row["workspace_id"],
            "pool_id": row["pool_id"],
            "issuer_user_id": row["issuer_user_id"],
            "subject_user_id": row["subject_user_id"],
            "subject_id": row["subject_id"],
            "expires_at": row["expires_at"],
            "claimed_at": row["claimed_at"],
            "decided_at": row["decided_at"],
            "decided_by_user_id": row["decided_by_user_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        if isinstance(worker_claim, dict):
            enrollment["worker_key_id"] = worker_claim.get("worker_key_id")
            if include_claim:
                enrollment["claim"] = worker_claim
                enrollment["proof_signature"] = record.get("proof_signature")

        result: dict[str, Any] = {"enrollment": enrollment}
        if isinstance(worker_claim, dict) and record.get("owner_consent_at") is not None:
            allocation_row = self.db.fetchone(
                "SELECT * FROM worker_allocations WHERE id=?",
                (config.get("allocation_id"),),
            )
            if allocation_row is None:
                result["allocation"] = {
                    "id": config.get("allocation_id"),
                    "worker_id": config.get("worker_id"),
                    "workspace_id": row["workspace_id"],
                    "pool_id": row["pool_id"],
                    "owner_consent_at": record["owner_consent_at"],
                    "workspace_approved_at": None,
                    "approved_by_user_id": None,
                    "status": "pending_workspace",
                }
            else:
                result["allocation"] = row_dict(
                    allocation_row, json_columns={"allocation_proof"}
                )
        if row["state"] == "active" and config.get("worker_id"):
            worker = self.db.fetchone("SELECT * FROM workers WHERE id=?", (config["worker_id"],))
            if worker is not None:
                result["worker"] = row_dict(worker, json_columns={"capabilities"})
        return result

    def create_worker_invite(
        self,
        *,
        issuer_user_id: str,
        workspace_id: str,
        pool_id: str,
        method: str,
        name: str,
        executor_type: str,
        executor_version: str,
        capacity: int,
        manager_broker_id: str | None,
        rate_microtokens_per_gpu_second: int,
        traffic_microtokens_per_gib: int,
        ttl_seconds: int,
    ) -> tuple[dict[str, Any], str]:
        """Issue a one-use, approval-required Invite without a bundled Worker key."""

        self.require_user(issuer_user_id)
        self.require_admin(workspace_id, issuer_user_id)
        if method != "invite_approval":
            raise RepositoryError(
                VALIDATION_FAILED,
                "INVALID_ENROLLMENT_METHOD",
                "Worker enrollment requires invite_approval.",
                422,
            )
        pool = self.db.fetchone(
            "SELECT id FROM pools WHERE id=? AND workspace_id=? AND status='active'",
            (pool_id, workspace_id),
        )
        if pool is None:
            raise RepositoryError(POOL_NOT_FOUND, "POOL_NOT_FOUND", "Pool not found.", 404)
        if manager_broker_id is not None:
            broker = self.db.fetchone(
                """SELECT id FROM brokers
                   WHERE id=? AND owner_user_id=? AND status='active'""",
                (manager_broker_id, issuer_user_id),
            )
            if broker is None:
                raise RepositoryError(
                    FORBIDDEN,
                    "BROKER_ACCESS_DENIED",
                    "Manager broker is not owned by the Worker owner.",
                    403,
                )
        if traffic_microtokens_per_gib != 0:
            raise RepositoryError(
                RATE_NOT_APPROVED,
                "TRAFFIC_BILLING_NOT_ENABLED",
                "Traffic billing is not enabled by the v1 rate policy.",
                409,
            )

        invite_id = new_id("inv")
        worker_id = new_id("wrk")
        allocation_id = new_id("alc")
        secret = secrets.token_urlsafe(32)
        stamp = now()
        record = {
            "config": {
                "version": 1,
                "worker_id": worker_id,
                "allocation_id": allocation_id,
                "name": name,
                "executor_type": executor_type,
                "executor_version": executor_version,
                "capacity": capacity,
                "manager_broker_id": manager_broker_id,
                "rate_microtokens_per_gpu_second": rate_microtokens_per_gpu_second,
                "traffic_microtokens_per_gib": traffic_microtokens_per_gib,
            }
        }
        with self.db.transaction(immediate=True) as conn:
            conn.execute(
                """INSERT INTO enrollments
                   (id,kind,method,state,workspace_id,pool_id,issuer_user_id,scopes,
                    invite_secret_hash,claim,expires_at,created_at,updated_at)
                   VALUES (?,'worker','invite_approval','issued',?,?,?,'[]',?,?,?,?,?)""",
                (
                    invite_id,
                    workspace_id,
                    pool_id,
                    issuer_user_id,
                    hashlib.sha256(secret.encode()).hexdigest(),
                    json_text(record),
                    stamp + ttl_seconds,
                    stamp,
                    stamp,
                ),
            )
            conn.execute(
                """INSERT INTO audit_events
                   (id,actor_type,actor_id,workspace_id,action,subject_type,subject_id,
                    safe_details,created_at)
                   VALUES (?,'user',?,?,'worker.enrollment_invited','enrollment',?,?,?)""",
                (
                    new_id("aud"),
                    issuer_user_id,
                    workspace_id,
                    invite_id,
                    json_text({"pool_id": pool_id, "worker_id": worker_id}),
                    stamp,
                ),
            )
        row = self.db.fetchone("SELECT * FROM enrollments WHERE id=?", (invite_id,))
        if row is None:
            raise RuntimeError("created Worker enrollment could not be reloaded")
        return self._worker_enrollment_value(row, include_claim=False), secret

    def claim_worker_invite(
        self,
        *,
        invite_id: str,
        secret: str,
        claim: dict[str, Any],
        proof_signature: str,
    ) -> dict[str, Any]:
        signing_key, _ = self._verify_worker_enrollment_claim(claim, proof_signature)
        if claim.get("invite_id") != invite_id:
            raise RepositoryError(
                INVITE_INVALID_OR_EXPIRED,
                "INVITE_INVALID_OR_EXPIRED",
                "The Worker invite is invalid, expired, or already used.",
                410,
            )
        stamp = now()
        secret_hash = hashlib.sha256(secret.encode()).hexdigest()
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM enrollments WHERE id=?", (invite_id,)).fetchone()
            secret_is_valid = bool(
                row is not None
                and row["kind"] == "worker"
                and row["method"] == "invite_approval"
                and row["invite_secret_hash"] is not None
                and secrets.compare_digest(row["invite_secret_hash"], secret_hash)
            )
            if not secret_is_valid:
                raise RepositoryError(
                    INVITE_INVALID_OR_EXPIRED,
                    "INVITE_INVALID_OR_EXPIRED",
                    "The Worker invite is invalid, expired, or already used.",
                    410,
                )
            record = self._worker_enrollment_record(row)
            existing_claim = record.get("worker_claim")
            existing_proof = record.get("proof_signature")
            if isinstance(existing_claim, dict) and (
                canonical_json(existing_claim) != canonical_json(claim)
                or not isinstance(existing_proof, str)
                or not secrets.compare_digest(existing_proof, proof_signature)
            ):
                raise RepositoryError(
                    IDEMPOTENCY_CONFLICT,
                    "IDEMPOTENCY_CONFLICT",
                    "The Worker invite was already claimed with different key material.",
                    409,
                )
            if row["state"] in {"pending", "active"}:
                if (
                    isinstance(existing_claim, dict)
                    and canonical_json(existing_claim) == canonical_json(claim)
                    and isinstance(existing_proof, str)
                    and secrets.compare_digest(existing_proof, proof_signature)
                ):
                    return self._worker_enrollment_value(row, include_claim=False)
                raise RepositoryError(
                    IDEMPOTENCY_CONFLICT,
                    "IDEMPOTENCY_CONFLICT",
                    "The Worker invite was already claimed with different key material.",
                    409,
                )
            valid_issued_state = (
                row["state"] == "issued"
                and row["expires_at"] is not None
                and row["expires_at"] > stamp
            )
            if not valid_issued_state:
                raise RepositoryError(
                    INVITE_INVALID_OR_EXPIRED,
                    "INVITE_INVALID_OR_EXPIRED",
                    "The Worker invite is invalid, expired, or already used.",
                    410,
                )
            fingerprint = hashlib.sha256(str(claim["signing_public_key"]).encode()).hexdigest()
            if row["subject_key_fingerprint"] and not secrets.compare_digest(
                row["subject_key_fingerprint"], fingerprint
            ):
                raise RepositoryError(
                    INVITE_INVALID_OR_EXPIRED,
                    "INVITE_INVALID_OR_EXPIRED",
                    "The Worker invite is not valid for this signing key.",
                    403,
                )
            config = record["config"]
            configured_claim_matches = (
                claim["executor_type"] == config.get("executor_type")
                and claim["executor_version"] == config.get("executor_version")
                and claim["capacity"] == config.get("capacity")
                and claim["worker_key_id"] == device_key_id(signing_key)
            )
            if not configured_claim_matches:
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "WORKER_INVITE_CONFIGURATION_MISMATCH",
                    "The Worker claim does not match the invited Executor configuration.",
                    422,
                )
            record.update(
                {
                    "worker_claim": claim,
                    "proof_signature": proof_signature,
                    "owner_consent_at": stamp,
                }
            )
            conn.execute(
                """UPDATE enrollments
                   SET state='pending',subject_user_id=issuer_user_id,subject_id=?,claim=?,
                       claimed_at=?,updated_at=? WHERE id=?""",
                (config["worker_id"], json_text(record), stamp, stamp, invite_id),
            )
            conn.execute(
                """INSERT INTO audit_events
                   (id,actor_type,actor_id,workspace_id,action,subject_type,subject_id,
                    safe_details,created_at)
                   VALUES (?,'worker',?,?,'worker.enrollment_claimed','enrollment',?,?,?)""",
                (
                    new_id("aud"),
                    claim["worker_key_id"],
                    row["workspace_id"],
                    invite_id,
                    json_text(
                        {
                            "claim_digest": "sha256:"
                            + hashlib.sha256(canonical_json(claim)).hexdigest(),
                            "worker_id": config["worker_id"],
                        }
                    ),
                    stamp,
                ),
            )
        claimed = self.db.fetchone("SELECT * FROM enrollments WHERE id=?", (invite_id,))
        if claimed is None:
            raise RuntimeError("claimed Worker enrollment could not be reloaded")
        return self._worker_enrollment_value(claimed, include_claim=False)

    def worker_enrollment_signing_material(self, enrollment_id: str) -> dict[str, str]:
        row = self.db.fetchone(
            "SELECT * FROM enrollments WHERE id=? AND kind='worker'", (enrollment_id,)
        )
        if row is None:
            raise RepositoryError(
                ENROLLMENT_NOT_FOUND, "ENROLLMENT_NOT_FOUND", "Enrollment not found.", 404
            )
        record = self._worker_enrollment_record(row)
        claim = record.get("worker_claim")
        if not isinstance(claim, dict):
            raise RepositoryError(
                ENROLLMENT_APPROVAL_REQUIRED,
                "ENROLLMENT_APPROVAL_REQUIRED",
                "The Worker has not claimed this enrollment.",
                409,
            )
        return {
            "worker_key_id": str(claim["worker_key_id"]),
            "signing_public_key": str(claim["signing_public_key"]),
        }

    def worker_enrollment_status(
        self,
        *,
        enrollment_id: str,
        admin_user_id: str | None = None,
        worker_key_id: str | None = None,
    ) -> dict[str, Any]:
        row = self.db.fetchone(
            "SELECT * FROM enrollments WHERE id=? AND kind='worker'", (enrollment_id,)
        )
        if row is None:
            raise RepositoryError(
                ENROLLMENT_NOT_FOUND, "ENROLLMENT_NOT_FOUND", "Enrollment not found.", 404
            )
        record = self._worker_enrollment_record(row)
        claim = record.get("worker_claim")
        if admin_user_id is not None:
            self.require_admin(row["workspace_id"], admin_user_id)
            if row["issuer_user_id"] != admin_user_id:
                raise RepositoryError(
                    FORBIDDEN,
                    "WORKER_ENROLLMENT_ISSUER_REQUIRED",
                    "Only the inviting Workspace admin may review this Worker.",
                    403,
                )
            return self._worker_enrollment_value(row, include_claim=True)
        if (
            worker_key_id is None
            or not isinstance(claim, dict)
            or not secrets.compare_digest(str(claim.get("worker_key_id") or ""), worker_key_id)
        ):
            raise RepositoryError(
                FORBIDDEN,
                "WORKER_ENROLLMENT_ACCESS_DENIED",
                "Worker enrollment access is denied.",
                403,
            )
        return self._worker_enrollment_value(row, include_claim=False)

    def decide_worker_enrollment(
        self,
        *,
        enrollment_id: str,
        admin_user_id: str,
        approve: bool,
        owner_certificate: str | None,
        allocation_proof: dict[str, Any] | None,
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM enrollments WHERE id=? AND kind='worker'", (enrollment_id,)
            ).fetchone()
            if row is None:
                raise RepositoryError(
                    ENROLLMENT_NOT_FOUND, "ENROLLMENT_NOT_FOUND", "Enrollment not found.", 404
                )
            membership = conn.execute(
                """SELECT role FROM memberships
                   WHERE workspace_id=? AND user_id=? AND status='active'""",
                (row["workspace_id"], admin_user_id),
            ).fetchone()
            if (
                membership is None
                or membership["role"] not in {"owner", "admin"}
                or row["issuer_user_id"] != admin_user_id
            ):
                raise RepositoryError(
                    FORBIDDEN,
                    "WORKER_ENROLLMENT_ISSUER_REQUIRED",
                    "Only the inviting Workspace admin may decide this Worker enrollment.",
                    403,
                )

            record = self._worker_enrollment_record(row)
            config = record["config"]
            claim = record.get("worker_claim")
            proof_signature = record.get("proof_signature")
            if not isinstance(claim, dict) or not isinstance(proof_signature, str):
                raise RepositoryError(
                    ENROLLMENT_APPROVAL_REQUIRED,
                    "ENROLLMENT_APPROVAL_REQUIRED",
                    "The Worker must claim the Invite before it can be decided.",
                    409,
                )

            if row["state"] == "rejected" and not approve:
                return self._worker_enrollment_value(row, include_claim=True)
            if row["state"] == "active" and approve:
                worker = conn.execute(
                    "SELECT certificate FROM workers WHERE id=?", (config["worker_id"],)
                ).fetchone()
                allocation = conn.execute(
                    "SELECT allocation_proof FROM worker_allocations WHERE id=?",
                    (config["allocation_id"],),
                ).fetchone()
                if worker is None or allocation is None:
                    raise RepositoryError(
                        VALIDATION_FAILED,
                        "WORKER_ENROLLMENT_RECORD_INVALID",
                        "The approved Worker enrollment record is incomplete.",
                        409,
                    )
                try:
                    stored_certificate = json.loads(worker["certificate"])
                    stored_allocation_proof = json.loads(allocation["allocation_proof"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise RepositoryError(
                        VALIDATION_FAILED,
                        "WORKER_ENROLLMENT_RECORD_INVALID",
                        "The approved Worker enrollment record is invalid.",
                        409,
                    ) from exc
                try:
                    same_material = bool(
                        owner_certificate is not None
                        and allocation_proof is not None
                        and canonical_json(stored_certificate)
                        == canonical_json(json.loads(owner_certificate))
                        and canonical_json(stored_allocation_proof)
                        == canonical_json(allocation_proof)
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    same_material = False
                if same_material:
                    return self._worker_enrollment_value(row, include_claim=True)
                raise RepositoryError(
                    IDEMPOTENCY_CONFLICT,
                    "IDEMPOTENCY_CONFLICT",
                    "The Worker enrollment was already approved with different material.",
                    409,
                )
            if row["state"] != "pending":
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "ENROLLMENT_STATE_CONFLICT",
                    "The Worker enrollment is not pending.",
                    409,
                )
            if not approve:
                conn.execute(
                    """UPDATE enrollments SET state='rejected',decided_at=?,
                       decided_by_user_id=?,updated_at=? WHERE id=?""",
                    (stamp, admin_user_id, stamp, enrollment_id),
                )
                conn.execute(
                    """INSERT INTO audit_events
                       (id,actor_type,actor_id,workspace_id,action,subject_type,subject_id,
                        safe_details,created_at)
                       VALUES (?,'user',?,?,'worker.enrollment_rejected','enrollment',?,'{}',?)""",
                    (new_id("aud"), admin_user_id, row["workspace_id"], enrollment_id, stamp),
                )
            else:
                if owner_certificate is None or allocation_proof is None:
                    raise RepositoryError(
                        VALIDATION_FAILED,
                        "WORKER_ENROLLMENT_APPROVAL_MATERIAL_REQUIRED",
                        "Approving a Worker requires its owner certificate and allocation proof.",
                        422,
                    )
                self._verify_worker_enrollment_claim(claim, proof_signature)
                pool = conn.execute(
                    """SELECT id FROM pools
                       WHERE id=? AND workspace_id=? AND status='active'""",
                    (row["pool_id"], row["workspace_id"]),
                ).fetchone()
                if pool is None:
                    raise RepositoryError(
                        POOL_NOT_FOUND,
                        "POOL_NOT_FOUND",
                        "The invited Pool is no longer active.",
                        404,
                    )
                if config.get("manager_broker_id") is not None:
                    broker = conn.execute(
                        """SELECT id FROM brokers
                           WHERE id=? AND owner_user_id=? AND status='active'""",
                        (config["manager_broker_id"], admin_user_id),
                    ).fetchone()
                    if broker is None:
                        raise RepositoryError(
                            FORBIDDEN,
                            "BROKER_ACCESS_DENIED",
                            "The invited manager Broker is no longer active.",
                            403,
                        )
                owner = conn.execute(
                    """SELECT root_signing_public_key FROM users
                       WHERE id=? AND status='active'""",
                    (admin_user_id,),
                ).fetchone()
                if owner is None:
                    raise RepositoryError(FORBIDDEN, "ACCESS_DENIED", "User is not active.", 403)
                try:
                    certificate = json.loads(owner_certificate)
                    manifest = certificate["manifest"]
                    root_key = b64url_decode(
                        owner["root_signing_public_key"], expected_length=32
                    )
                    expected_root_id = root_signing_key_id(root_key)
                    issued_at = manifest["issued_at"]
                    certificate_is_valid = (
                        set(certificate) == {"manifest", "signer_key_id", "signature"}
                        and set(manifest)
                        == {
                            "version",
                            "kind",
                            "owner_root_key_id",
                            "worker_key_id",
                            "worker_signing_public_key",
                            "worker_encryption_public_key",
                            "issued_at",
                        }
                        and isinstance(issued_at, int)
                        and not isinstance(issued_at, bool)
                        and issued_at >= int(row["claimed_at"]) - 300
                        and issued_at <= int(stamp) + 300
                        and certificate["signer_key_id"] == expected_root_id
                        and manifest["version"] == 1
                        and manifest["kind"] == "vgen-worker-owner-certificate"
                        and manifest["owner_root_key_id"] == expected_root_id
                        and manifest["worker_key_id"] == claim["worker_key_id"]
                        and manifest["worker_signing_public_key"]
                        == claim["signing_public_key"]
                        and manifest["worker_encryption_public_key"]
                        == claim["encryption_public_key"]
                        and verify_key_manifest(certificate, root_key)
                    )
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    certificate_is_valid = False
                    certificate = {}
                    root_key = b""
                    expected_root_id = ""
                if not certificate_is_valid:
                    raise RepositoryError(
                        DEVICE_CERTIFICATE_INVALID,
                        "DEVICE_CERTIFICATE_INVALID",
                        "The Worker owner certificate is invalid.",
                        401,
                    )
                try:
                    proof_payload = allocation_proof["payload"]
                    expected_proof = build_allocation_proof_payload(
                        allocation_id=config["allocation_id"],
                        workspace_id=row["workspace_id"],
                        pool_id=row["pool_id"],
                        worker_id=config["worker_id"],
                        worker_signing_public_key=claim["signing_public_key"],
                        worker_encryption_public_key=claim["encryption_public_key"],
                        worker_certificate=certificate,
                        owner_consent_at=float(record["owner_consent_at"]),
                        approver_root_key_id=expected_root_id,
                        issued_at=int(proof_payload["issued_at"]),
                    )
                    allocation_is_valid = (
                        set(allocation_proof) == {"payload", "signer_key_id", "signature"}
                        and set(proof_payload) == set(expected_proof)
                        and int(proof_payload["issued_at"]) >= int(row["claimed_at"]) - 300
                        and verify_allocation_proof(
                            allocation_proof, root_key, expected=expected_proof
                        )
                    )
                except (KeyError, TypeError, ValueError):
                    allocation_is_valid = False
                if not allocation_is_valid:
                    raise RepositoryError(
                        ALLOCATION_PROOF_INVALID,
                        "ALLOCATION_PROOF_INVALID",
                        "The Workspace allocation proof is invalid.",
                        422,
                    )

                conn.execute(
                    """INSERT INTO workers
                       (id,owner_user_id,manager_broker_id,name,signing_public_key,
                        encryption_public_key,certificate,executor_type,executor_version,
                        capabilities,capacity,status,created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,'offline',?,?)""",
                    (
                        config["worker_id"],
                        admin_user_id,
                        config.get("manager_broker_id"),
                        claim["name"],
                        claim["signing_public_key"],
                        claim["encryption_public_key"],
                        json_text(certificate),
                        claim["executor_type"],
                        claim["executor_version"],
                        json_text(claim["capabilities"]),
                        claim["capacity"],
                        stamp,
                        stamp,
                    ),
                )
                conn.execute(
                    """INSERT INTO worker_allocations
                       (id,worker_id,workspace_id,pool_id,owner_consent_at,
                        workspace_approved_at,approved_by_user_id,allocation_proof,status,
                        created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,'active',?,?)""",
                    (
                        config["allocation_id"],
                        config["worker_id"],
                        row["workspace_id"],
                        row["pool_id"],
                        record["owner_consent_at"],
                        stamp,
                        admin_user_id,
                        json_text(allocation_proof),
                        row["claimed_at"],
                        stamp,
                    ),
                )
                conn.execute(
                    """UPDATE rate_cards SET status='superseded'
                       WHERE worker_id=? AND workspace_id=? AND status='approved'""",
                    (config["worker_id"], row["workspace_id"]),
                )
                conn.execute(
                    """INSERT INTO rate_cards
                       (id,worker_id,workspace_id,proposed_by_user_id,approved_by_user_id,
                        rate_microtokens_per_gpu_second,traffic_microtokens_per_gib,
                        formula_version,status,proposed_at,decided_at)
                       VALUES (?,?,?,?,?,?,?,1,'approved',?,?)""",
                    (
                        new_id("rat"),
                        config["worker_id"],
                        row["workspace_id"],
                        admin_user_id,
                        admin_user_id,
                        config["rate_microtokens_per_gpu_second"],
                        config["traffic_microtokens_per_gib"],
                        stamp,
                        stamp,
                    ),
                )
                conn.execute(
                    """UPDATE enrollments SET state='active',decided_at=?,
                       decided_by_user_id=?,updated_at=? WHERE id=?""",
                    (stamp, admin_user_id, stamp, enrollment_id),
                )
                conn.execute(
                    """INSERT INTO audit_events
                       (id,actor_type,actor_id,workspace_id,action,subject_type,subject_id,
                        safe_details,created_at)
                       VALUES (?,'user',?,?,'worker.enrollment_approved','worker',?,?,?)""",
                    (
                        new_id("aud"),
                        admin_user_id,
                        row["workspace_id"],
                        config["worker_id"],
                        json_text(
                            {
                                "allocation_id": config["allocation_id"],
                                "pool_id": row["pool_id"],
                            }
                        ),
                        stamp,
                    ),
                )
        decided = self.db.fetchone("SELECT * FROM enrollments WHERE id=?", (enrollment_id,))
        if decided is None:
            raise RuntimeError("decided Worker enrollment could not be reloaded")
        return self._worker_enrollment_value(decided, include_claim=True)

    def enroll_user(
        self,
        *,
        invite_id: str,
        secret: str,
        claim: dict[str, Any],
        proof_signature: str,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Claim a User Invite with semantic retry after a lost HTTP response."""

        if claim.get("invite_id") != invite_id or not verify_user_registration_claim(
            claim, proof_signature
        ):
            raise RepositoryError(
                SIGNATURE_INVALID,
                "SIGNATURE_INVALID",
                "The User enrollment claim or Device proof is invalid.",
                401,
            )
        registration_record = {
            "registration_claim": claim,
            "proof_signature": proof_signature,
        }
        record_bytes = canonical_json(registration_record)
        secret_hash = hashlib.sha256(secret.encode()).hexdigest()
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            invite = conn.execute("SELECT * FROM enrollments WHERE id=?", (invite_id,)).fetchone()
            secret_matches = bool(
                invite is not None
                and invite["kind"] == "user"
                and invite["invite_secret_hash"] is not None
                and secrets.compare_digest(invite["invite_secret_hash"], secret_hash)
            )
            if not secret_matches:
                raise RepositoryError(
                    INVITE_INVALID_OR_EXPIRED,
                    "INVITE_INVALID_OR_EXPIRED",
                    "The invite is invalid, expired, or already used.",
                    410,
                )
            if invite["state"] in {"pending", "active"}:
                try:
                    stored_record = json.loads(invite["claim"] or "null")
                    same_claim = canonical_json(stored_record) == record_bytes
                except (TypeError, ValueError, json.JSONDecodeError):
                    same_claim = False
                if not same_claim:
                    raise RepositoryError(
                        IDEMPOTENCY_CONFLICT,
                        "IDEMPOTENCY_CONFLICT",
                        "The User invite was already claimed with different identity material.",
                        409,
                    )
                user_id = str(invite["subject_user_id"] or "")
                stored_device_id = str(invite["subject_id"] or "")
                existing_user = conn.execute(
                    "SELECT * FROM users WHERE id=? AND status='active'", (user_id,)
                ).fetchone()
                existing_device = conn.execute(
                    """SELECT * FROM devices
                       WHERE id=? AND user_id=? AND status='active'""",
                    (stored_device_id, user_id),
                ).fetchone()
                if (
                    existing_user is None
                    or existing_device is None
                    or stored_device_id != claim["device_id"]
                    or existing_user["display_name"] != claim["display_name"]
                    or existing_user["root_signing_public_key"]
                    != claim["root_signing_public_key"]
                    or existing_user["root_encryption_public_key"]
                    != claim["root_encryption_public_key"]
                    or existing_device["name"] != claim["device_name"]
                    or existing_device["signing_public_key"]
                    != claim["device_signing_public_key"]
                    or existing_device["encryption_public_key"]
                    != claim["device_encryption_public_key"]
                    or canonical_json(json.loads(existing_device["certificate"]))
                    != canonical_json(claim["device_certificate"])
                ):
                    raise RepositoryError(
                        VALIDATION_FAILED,
                        "USER_ENROLLMENT_RECORD_INVALID",
                        "The User enrollment record is invalid.",
                        409,
                    )
            else:
                valid_issued = (
                    invite["state"] == "issued"
                    and invite["expires_at"] is not None
                    and invite["expires_at"] > stamp
                )
                if not valid_issued:
                    raise RepositoryError(
                        INVITE_INVALID_OR_EXPIRED,
                        "INVITE_INVALID_OR_EXPIRED",
                        "The invite is invalid, expired, or already used.",
                        410,
                    )
                fingerprint = hashlib.sha256(
                    str(claim["device_signing_public_key"]).encode()
                ).hexdigest()
                if (
                    invite["subject_key_fingerprint"]
                    and invite["subject_key_fingerprint"] != fingerprint
                ):
                    raise RepositoryError(
                        INVITE_INVALID_OR_EXPIRED,
                        "INVITE_INVALID_OR_EXPIRED",
                        "The invite is not valid for this device key.",
                        403,
                    )
                user_id = new_id("usr")
                conn.execute(
                    """INSERT INTO users
                       (id,display_name,root_signing_public_key,root_encryption_public_key,status,is_operator,created_at,updated_at)
                       VALUES (?,?,?,?, 'active',0,?,?)""",
                    (
                        user_id,
                        claim["display_name"],
                        claim["root_signing_public_key"],
                        claim["root_encryption_public_key"],
                        stamp,
                        stamp,
                    ),
                )
                conn.execute(
                    """INSERT INTO devices
                       (id,user_id,name,signing_public_key,encryption_public_key,certificate,status,created_at,last_seen_at)
                       VALUES (?,?,?,?,?,?,'active',?,?)""",
                    (
                        claim["device_id"],
                        user_id,
                        claim["device_name"],
                        claim["device_signing_public_key"],
                        claim["device_encryption_public_key"],
                        json_text(claim["device_certificate"]),
                        stamp,
                        stamp,
                    ),
                )
                state = "active" if invite["method"] == "direct_invite" else "pending"
                conn.execute(
                    """UPDATE enrollments
                       SET state=?,subject_user_id=?,subject_id=?,claim=?,claimed_at=?,updated_at=?
                       WHERE id=?""",
                    (
                        state,
                        user_id,
                        claim["device_id"],
                        json_text(registration_record),
                        stamp,
                        stamp,
                        invite_id,
                    ),
                )
                if state == "active" and invite["workspace_id"]:
                    role = (
                        invite["relationship"]
                        if invite["relationship"] in ("admin", "member")
                        else "member"
                    )
                    conn.execute(
                        """INSERT INTO memberships(workspace_id,user_id,role,status,created_at)
                           VALUES (?,?,?,'active',?)""",
                        (invite["workspace_id"], user_id, role, stamp),
                    )
        return (
            row_dict(self.db.fetchone("SELECT * FROM users WHERE id=?", (user_id,))),
            row_dict(self.db.fetchone("SELECT * FROM devices WHERE id=?", (claim["device_id"],))),
            self.enrollment(invite_id),
        )

    def enroll_device(
        self,
        *,
        invite_id: str,
        secret: str,
        root_signing_public_key: str,
        root_encryption_public_key: str,
        device_id: str,
        device_name: str,
        device_signing_public_key: str,
        device_encryption_public_key: str,
        device_certificate: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            invite = conn.execute("SELECT * FROM enrollments WHERE id=?", (invite_id,)).fetchone()
            valid = (
                invite is not None
                and invite["kind"] == "broker_device"
                and invite["state"] == "issued"
                and invite["expires_at"] is not None
                and invite["expires_at"] > stamp
                and secrets.compare_digest(
                    invite["invite_secret_hash"], hashlib.sha256(secret.encode()).hexdigest()
                )
            )
            if not valid:
                raise RepositoryError(
                    INVITE_INVALID_OR_EXPIRED,
                    "INVITE_INVALID_OR_EXPIRED",
                    "The invite is invalid or expired.",
                    410,
                )
            user = conn.execute(
                """SELECT * FROM users WHERE root_signing_public_key=?
                   AND root_encryption_public_key=? AND status='active'""",
                (root_signing_public_key, root_encryption_public_key),
            ).fetchone()
            if user is None:
                raise RepositoryError(
                    FORBIDDEN, "USER_IDENTITY_NOT_FOUND", "No active user owns this root key.", 403
                )
            fingerprint = hashlib.sha256(device_signing_public_key.encode()).hexdigest()
            if (
                invite["subject_key_fingerprint"]
                and invite["subject_key_fingerprint"] != fingerprint
            ):
                raise RepositoryError(
                    INVITE_INVALID_OR_EXPIRED,
                    "INVITE_INVALID_OR_EXPIRED",
                    "Invite key binding does not match.",
                    403,
                )
            state = "active" if invite["method"] == "direct_invite" else "pending"
            claim = {
                "device_id": device_id,
                "device_name": device_name,
                "device_signing_public_key": device_signing_public_key,
                "device_encryption_public_key": device_encryption_public_key,
                "device_certificate": device_certificate,
            }
            if state == "active":
                conn.execute(
                    """INSERT INTO devices
                       (id,user_id,name,signing_public_key,encryption_public_key,certificate,status,created_at,last_seen_at)
                       VALUES (?,?,?,?,?,?,'active',?,?)""",
                    (
                        device_id,
                        user["id"],
                        device_name,
                        device_signing_public_key,
                        device_encryption_public_key,
                        json_text(device_certificate),
                        stamp,
                        stamp,
                    ),
                )
            conn.execute(
                """UPDATE enrollments SET state=?,subject_user_id=?,subject_id=?,claim=?,claimed_at=?,updated_at=?
                   WHERE id=?""",
                (state, user["id"], device_id, json_text(claim), stamp, stamp, invite_id),
            )
        device = (
            row_dict(self.db.fetchone("SELECT * FROM devices WHERE id=?", (device_id,)))
            if state == "active"
            else {"id": device_id, "user_id": user["id"], "name": device_name, "status": "pending"}
        )
        return (
            row_dict(self.db.fetchone("SELECT * FROM users WHERE id=?", (user["id"],))),
            device,
            self.enrollment(invite_id),
        )

    def enroll_service(
        self,
        *,
        invite_id: str,
        secret: str,
        name: str,
        signing_public_key: str,
        encryption_public_key: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Claim a Service invite after the route verified key possession."""

        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            invite = conn.execute("SELECT * FROM enrollments WHERE id=?", (invite_id,)).fetchone()
            valid = (
                invite is not None
                and invite["kind"] == "service"
                and invite["workspace_id"] is not None
                and invite["state"] == "issued"
                and invite["expires_at"] is not None
                and invite["expires_at"] > stamp
                and invite["invite_secret_hash"] is not None
                and secrets.compare_digest(
                    invite["invite_secret_hash"], hashlib.sha256(secret.encode()).hexdigest()
                )
            )
            fingerprint = hashlib.sha256(signing_public_key.encode()).hexdigest()
            valid = bool(
                valid
                and (
                    not invite["subject_key_fingerprint"]
                    or invite["subject_key_fingerprint"] == fingerprint
                )
            )
            if not valid:
                raise RepositoryError(
                    INVITE_INVALID_OR_EXPIRED,
                    "INVITE_INVALID_OR_EXPIRED",
                    "The Service invite is invalid, expired, or already used.",
                    410,
                )
            scopes = json.loads(invite["scopes"] or "[]")
            if not scopes or not set(scopes) <= SERVICE_SCOPES:
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "INVALID_SERVICE_SCOPES",
                    "The Service invite contains invalid scopes.",
                    422,
                )
            service_id = new_id("svc")
            state = "active" if invite["method"] == "direct_invite" else "pending"
            conn.execute(
                """INSERT INTO services
                   (id,workspace_id,name,signing_public_key,encryption_public_key,scopes,status,
                    created_by_user_id,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    service_id,
                    invite["workspace_id"],
                    name,
                    signing_public_key,
                    encryption_public_key,
                    json_text(scopes),
                    state,
                    invite["issuer_user_id"],
                    stamp,
                    stamp,
                ),
            )
            conn.execute(
                """UPDATE enrollments SET state=?,subject_id=?,claim=?,claimed_at=?,updated_at=?
                   WHERE id=?""",
                (
                    state,
                    service_id,
                    json_text(
                        {
                            "name": name,
                            "signing_public_key": signing_public_key,
                            "encryption_public_key": encryption_public_key,
                        }
                    ),
                    stamp,
                    stamp,
                    invite_id,
                ),
            )
        return (
            row_dict(
                self.db.fetchone("SELECT * FROM services WHERE id=?", (service_id,)),
                json_columns={"scopes"},
            ),
            self.enrollment(invite_id),
        )

    def apply(
        self,
        *,
        subject_user_id: str,
        subject_device_id: str,
        application_id: str,
        workspace_id: str,
        pool_id: str | None,
        kind: str,
        claim: dict[str, Any],
        proof_signature: str,
        relationship: str | None,
    ) -> dict[str, Any]:
        user = self.require_user(subject_user_id)
        device = self.db.fetchone(
            """SELECT * FROM devices
               WHERE id=? AND user_id=? AND status='active'""",
            (subject_device_id, subject_user_id),
        )
        valid_claim = bool(
            device is not None
            and claim.get("invite_id") == application_id
            and claim.get("root_signing_public_key") == user["root_signing_public_key"]
            and claim.get("root_encryption_public_key") == user["root_encryption_public_key"]
            and claim.get("device_id") == subject_device_id
            and claim.get("device_signing_public_key") == device["signing_public_key"]
            and claim.get("device_encryption_public_key") == device["encryption_public_key"]
            and canonical_json(claim.get("device_certificate", {}))
            == canonical_json(json.loads(device["certificate"]))
            and verify_user_registration_claim(claim, proof_signature)
        )
        if not valid_claim:
            raise RepositoryError(
                SIGNATURE_INVALID,
                "SIGNATURE_INVALID",
                "The Workspace application identity claim is invalid.",
                401,
            )
        workspace = self.db.fetchone(
            "SELECT * FROM workspaces WHERE id=? AND status='active'", (workspace_id,)
        )
        if workspace is None:
            raise RepositoryError(
                WORKSPACE_NOT_FOUND, "WORKSPACE_NOT_FOUND", "Workspace not found.", 404
            )
        policy = json.loads(workspace["enrollment_policy"] or "{}")
        if policy.get(kind, "closed") == "closed":
            raise RepositoryError(
                240003, "ENROLLMENT_CLOSED", "Enrollment is closed for this subject type.", 403
            )
        enrollment_id = application_id
        if not enrollment_id.startswith("app_"):
            raise RepositoryError(
                VALIDATION_FAILED,
                "APPLICATION_ID_INVALID",
                "The Workspace application ID is invalid.",
                422,
            )
        stamp = now()
        self.db.execute(
            """INSERT INTO enrollments
               (id,kind,method,state,workspace_id,pool_id,subject_user_id,subject_id,
                claim,relationship,created_at,updated_at)
               VALUES (?,?,'apply_approval','pending',?,?,?,?,?,?,?,?)""",
            (
                enrollment_id,
                kind,
                workspace_id,
                pool_id,
                subject_user_id,
                subject_device_id,
                json_text(
                    {"registration_claim": claim, "proof_signature": proof_signature}
                ),
                relationship,
                stamp,
                stamp,
            ),
        )
        return self.enrollment(enrollment_id)

    def claim_invite(
        self,
        *,
        invite_id: str,
        secret: str,
        subject_user_id: str,
        subject_device_id: str,
        subject_key_fingerprint: str,
        claim: dict[str, Any],
        proof_signature: str,
    ) -> dict[str, Any]:
        """Claim only an existing User's Workspace membership invite.

        User, Broker Device and Service credentials have dedicated enrollment
        routes which validate their own key material.  Worker allocation is an
        owner-offer/admin-proof relationship and never consumes an Invite.
        Keeping this route membership-only prevents a credential for one kind
        from being reinterpreted as another kind with a caller-supplied ID.
        """
        user = self.require_user(subject_user_id)
        device = self.db.fetchone(
            """SELECT * FROM devices
               WHERE id=? AND user_id=? AND status='active'""",
            (subject_device_id, subject_user_id),
        )
        claim_matches_authenticated_identity = bool(
            device is not None
            and claim.get("invite_id") == invite_id
            and claim.get("root_signing_public_key") == user["root_signing_public_key"]
            and claim.get("root_encryption_public_key") == user["root_encryption_public_key"]
            and claim.get("device_id") == subject_device_id
            and claim.get("device_signing_public_key") == device["signing_public_key"]
            and claim.get("device_encryption_public_key") == device["encryption_public_key"]
            and canonical_json(claim.get("device_certificate", {}))
            == canonical_json(json.loads(device["certificate"]))
            and verify_user_registration_claim(claim, proof_signature)
        )
        if not claim_matches_authenticated_identity:
            raise RepositoryError(
                SIGNATURE_INVALID,
                "SIGNATURE_INVALID",
                "The Workspace member claim does not match the authenticated User and Device.",
                401,
            )
        record = {"registration_claim": claim, "proof_signature": proof_signature}
        record_bytes = canonical_json(record)
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM enrollments WHERE id=?", (invite_id,)).fetchone()
            secret_valid = (
                row is not None
                and row["kind"] == "workspace_member"
                and row["invite_secret_hash"] is not None
                and secrets.compare_digest(
                    row["invite_secret_hash"], hashlib.sha256(secret.encode()).hexdigest()
                )
                and (
                    not row["subject_key_fingerprint"]
                    or row["subject_key_fingerprint"] == subject_key_fingerprint
                )
            )
            if not secret_valid:
                raise RepositoryError(
                    INVITE_INVALID_OR_EXPIRED,
                    "INVITE_INVALID_OR_EXPIRED",
                    "The invite is invalid, expired, or already used.",
                    410,
                )
            if row["state"] in {"pending", "active"}:
                try:
                    stored_record = json.loads(row["claim"] or "null")
                    same_record = canonical_json(stored_record) == record_bytes
                except (TypeError, ValueError, json.JSONDecodeError):
                    same_record = False
                if (
                    same_record
                    and row["subject_user_id"] == subject_user_id
                    and row["subject_id"] == subject_device_id
                ):
                    return self.enrollment(invite_id)
                raise RepositoryError(
                    IDEMPOTENCY_CONFLICT,
                    "IDEMPOTENCY_CONFLICT",
                    "The Workspace Invite was already claimed with different identity material.",
                    409,
                )
            valid_issued = (
                row["state"] == "issued"
                and row["expires_at"] is not None
                and row["expires_at"] > stamp
            )
            if not valid_issued:
                raise RepositoryError(
                    INVITE_INVALID_OR_EXPIRED,
                    "INVITE_INVALID_OR_EXPIRED",
                    "The invite is invalid, expired, or already used.",
                    410,
                )
            state = "active" if row["method"] == "direct_invite" else "pending"
            conn.execute(
                """UPDATE enrollments SET state=?,subject_user_id=?,subject_id=?,claim=?,claimed_at=?,updated_at=?
                   WHERE id=?""",
                (
                    state,
                    subject_user_id,
                    subject_device_id,
                    json_text(record),
                    stamp,
                    stamp,
                    invite_id,
                ),
            )
            if state == "active":
                self._activate_enrollment(
                    conn,
                    row,
                    subject_user_id,
                    subject_device_id,
                    row["issuer_user_id"],
                    stamp,
                )
        result = self.enrollment(invite_id)
        if result["state"] == "pending":
            result["approval_required"] = True
        return result

    def decide_enrollment(
        self, *, enrollment_id: str, admin_user_id: str, approve: bool
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM enrollments WHERE id=?", (enrollment_id,)).fetchone()
            if row is None:
                raise RepositoryError(
                    ENROLLMENT_NOT_FOUND, "ENROLLMENT_NOT_FOUND", "Enrollment not found.", 404
                )
            if row["workspace_id"]:
                admin = conn.execute(
                    """SELECT role FROM memberships WHERE workspace_id=? AND user_id=? AND status='active'""",
                    (row["workspace_id"], admin_user_id),
                ).fetchone()
                required_roles = (
                    {"owner"}
                    if row["kind"] in {"user", "workspace_member", "service"}
                    else {"owner", "admin"}
                )
                if admin is None or admin["role"] not in required_roles:
                    raise RepositoryError(
                        FORBIDDEN,
                        "WORKSPACE_OWNER_REQUIRED"
                        if required_roles == {"owner"}
                        else "WORKSPACE_ADMIN_REQUIRED",
                        "Workspace Owner access is required for recipient enrollment."
                        if required_roles == {"owner"}
                        else "Workspace admin access is required.",
                        403,
                    )
            else:
                self.require_user(admin_user_id)
            if row["state"] != "pending":
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "ENROLLMENT_STATE_CONFLICT",
                    "Enrollment is not pending.",
                    409,
                )
            state = "active" if approve else "rejected"
            conn.execute(
                """UPDATE enrollments SET state=?,decided_at=?,decided_by_user_id=?,updated_at=? WHERE id=?""",
                (state, stamp, admin_user_id, stamp, enrollment_id),
            )
            if approve:
                self._activate_enrollment(
                    conn, row, row["subject_user_id"], row["subject_id"], admin_user_id, stamp
                )
        return self.enrollment(enrollment_id)

    def revoke_enrollment(self, *, enrollment_id: str, admin_user_id: str) -> dict[str, Any]:
        """Revoke an admission and the active relationship it created."""

        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM enrollments WHERE id=?", (enrollment_id,)).fetchone()
            if row is None:
                raise RepositoryError(
                    ENROLLMENT_NOT_FOUND, "ENROLLMENT_NOT_FOUND", "Enrollment not found.", 404
                )
            if row["workspace_id"]:
                admin = conn.execute(
                    """SELECT role FROM memberships
                       WHERE workspace_id=? AND user_id=? AND status='active'""",
                    (row["workspace_id"], admin_user_id),
                ).fetchone()
                if admin is None or admin["role"] not in ("owner", "admin"):
                    raise RepositoryError(
                        FORBIDDEN,
                        "WORKSPACE_ADMIN_REQUIRED",
                        "Workspace admin access is required.",
                        403,
                    )
            else:
                self.require_user(admin_user_id)
            if row["state"] == "revoked":
                return self.enrollment(enrollment_id)
            if row["state"] not in ("issued", "claimed", "pending", "active"):
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "ENROLLMENT_STATE_CONFLICT",
                    "This enrollment cannot be revoked from its current state.",
                    409,
                )
            if row["state"] == "active":
                if (
                    row["kind"] in ("workspace_member", "user")
                    and row["workspace_id"]
                    and row["subject_user_id"]
                ):
                    conn.execute(
                        """UPDATE memberships SET status='revoked',revoked_at=?
                           WHERE workspace_id=? AND user_id=? AND role!='owner'""",
                        (stamp, row["workspace_id"], row["subject_user_id"]),
                    )
                elif row["kind"] == "worker_allocation" and row["pool_id"] and row["subject_id"]:
                    conn.execute(
                        """UPDATE worker_allocations SET status='revoked',revoked_at=?,updated_at=?
                           WHERE worker_id=? AND pool_id=?""",
                        (stamp, stamp, row["subject_id"], row["pool_id"]),
                    )
                elif row["kind"] == "broker_device" and row["subject_id"]:
                    conn.execute(
                        "UPDATE devices SET status='revoked',revoked_at=? WHERE id=?",
                        (stamp, row["subject_id"]),
                    )
                    conn.execute(
                        """UPDATE sessions SET revoked_at=?
                           WHERE principal_type='device' AND principal_id=? AND revoked_at IS NULL""",
                        (stamp, row["subject_id"]),
                    )
                elif row["kind"] == "service" and row["subject_id"]:
                    conn.execute(
                        "UPDATE services SET status='revoked',revoked_at=?,updated_at=? WHERE id=?",
                        (stamp, stamp, row["subject_id"]),
                    )
                    conn.execute(
                        """UPDATE sessions SET revoked_at=?
                           WHERE principal_type='service' AND principal_id=? AND revoked_at IS NULL""",
                        (stamp, row["subject_id"]),
                    )
            conn.execute(
                """UPDATE enrollments SET state='revoked',decided_at=?,decided_by_user_id=?,updated_at=?
                   WHERE id=?""",
                (stamp, admin_user_id, stamp, enrollment_id),
            )
        return self.enrollment(enrollment_id)

    def _activate_enrollment(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        subject_user_id: str | None,
        subject_id: str | None,
        approver_id: str,
        stamp: float,
    ) -> None:
        if row["kind"] in ("user", "workspace_member") and row["workspace_id"] and subject_user_id:
            role = row["relationship"] if row["relationship"] in ("admin", "member") else "member"
            conn.execute(
                """INSERT INTO memberships(workspace_id,user_id,role,status,created_at)
                   VALUES (?,?,?,'active',?)
                   ON CONFLICT(workspace_id,user_id) DO UPDATE SET role=excluded.role,status='active',revoked_at=NULL""",
                (row["workspace_id"], subject_user_id, role, stamp),
            )
        elif row["kind"] == "broker_device" and subject_user_id and subject_id:
            claim = json.loads(row["claim"] or "{}")
            conn.execute(
                """INSERT INTO devices
                   (id,user_id,name,signing_public_key,encryption_public_key,certificate,status,created_at,last_seen_at)
                   VALUES (?,?,?,?,?,?,'active',?,?)""",
                (
                    subject_id,
                    subject_user_id,
                    claim["device_name"],
                    claim["device_signing_public_key"],
                    claim["device_encryption_public_key"],
                    json_text(claim["device_certificate"]),
                    stamp,
                    stamp,
                ),
            )
        elif row["kind"] == "worker_allocation" and row["pool_id"] and subject_id:
            allocation = conn.execute(
                "SELECT * FROM worker_allocations WHERE worker_id=? AND pool_id=?",
                (subject_id, row["pool_id"]),
            ).fetchone()
            if allocation:
                conn.execute(
                    """UPDATE worker_allocations SET workspace_approved_at=?,approved_by_user_id=?,status='active',updated_at=?
                       WHERE id=?""",
                    (stamp, approver_id, stamp, allocation["id"]),
                )
        elif row["kind"] == "service" and subject_id:
            conn.execute(
                """UPDATE services SET status='active',updated_at=?
                   WHERE id=? AND status='pending'""",
                (stamp, subject_id),
            )

    # ------------------------------------------------------------------- workers

    def create_worker(
        self,
        *,
        owner_user_id: str,
        manager_broker_id: str | None,
        name: str,
        signing_public_key: str,
        encryption_public_key: str,
        certificate: str | None,
        executor_type: str,
        executor_version: str,
        capabilities: dict[str, Any],
        capacity: int,
    ) -> dict[str, Any]:
        self.require_user(owner_user_id)
        if manager_broker_id:
            broker = self.db.fetchone(
                "SELECT * FROM brokers WHERE id=? AND owner_user_id=? AND status='active'",
                (manager_broker_id, owner_user_id),
            )
            if broker is None:
                raise RepositoryError(
                    FORBIDDEN,
                    "BROKER_ACCESS_DENIED",
                    "Manager broker is not owned by the worker owner.",
                    403,
                )
        stamp = now()
        capabilities_json = json_text(capabilities)
        with self.db.transaction(immediate=True) as conn:
            existing = conn.execute(
                "SELECT * FROM workers WHERE signing_public_key=?", (signing_public_key,)
            ).fetchone()
            if existing is not None:
                matches = (
                    existing["owner_user_id"] == owner_user_id
                    and existing["manager_broker_id"] == manager_broker_id
                    and existing["name"] == name
                    and existing["encryption_public_key"] == encryption_public_key
                    and existing["certificate"] == certificate
                    and existing["executor_type"] == executor_type
                    and existing["executor_version"] == executor_version
                    and existing["capabilities"] == capabilities_json
                    and existing["capacity"] == capacity
                )
                if not matches:
                    raise RepositoryError(
                        600002,
                        "IDEMPOTENCY_CONFLICT",
                        "The Worker signing key is already registered with different attributes.",
                        409,
                    )
                return row_dict(existing, json_columns={"capabilities"})
            worker_id = new_id("wrk")
            conn.execute(
                """INSERT INTO workers
                   (id,owner_user_id,manager_broker_id,name,signing_public_key,encryption_public_key,certificate,
                    executor_type,executor_version,capabilities,capacity,status,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,'offline',?,?)""",
                (
                    worker_id,
                    owner_user_id,
                    manager_broker_id,
                    name,
                    signing_public_key,
                    encryption_public_key,
                    certificate,
                    executor_type,
                    executor_version,
                    capabilities_json,
                    capacity,
                    stamp,
                    stamp,
                ),
            )
        return row_dict(
            self.db.fetchone("SELECT * FROM workers WHERE id=?", (worker_id,)),
            json_columns={"capabilities"},
        )

    def list_workers(
        self, *, user_id: str, workspace_id: str | None = None
    ) -> list[dict[str, Any]]:
        if workspace_id:
            self.require_member(workspace_id, user_id)
            rows = self.db.fetchall(
                """SELECT DISTINCT w.* FROM workers w
                   JOIN worker_allocations a ON a.worker_id=w.id
                   WHERE a.workspace_id=? AND a.status!='revoked' ORDER BY w.created_at""",
                (workspace_id,),
            )
        else:
            self.require_user(user_id)
            rows = self.db.fetchall(
                "SELECT * FROM workers WHERE owner_user_id=? ORDER BY created_at", (user_id,)
            )
        return [row_dict(row, json_columns={"capabilities"}) for row in rows]

    def list_allocations(self, *, workspace_id: str, user_id: str) -> list[dict[str, Any]]:
        self.require_member(workspace_id, user_id)
        return [
            row_dict(row, json_columns={"allocation_proof"})
            for row in self.db.fetchall(
                """SELECT a.* FROM worker_allocations a
                   WHERE a.workspace_id=? ORDER BY a.created_at""",
                (workspace_id,),
            )
        ]

    def get_allocation(self, *, allocation_id: str, user_id: str) -> dict[str, Any]:
        row = self.db.fetchone(
            """SELECT a.*,w.signing_public_key AS worker_signing_public_key,
                      w.encryption_public_key AS worker_encryption_public_key,
                      w.certificate AS worker_certificate
               FROM worker_allocations a JOIN workers w ON w.id=a.worker_id
               WHERE a.id=?""",
            (allocation_id,),
        )
        if row is None:
            raise RepositoryError(
                WORKER_ALLOCATION_NOT_FOUND,
                "WORKER_ALLOCATION_NOT_FOUND",
                "Worker allocation not found.",
                404,
            )
        self.require_member(row["workspace_id"], user_id)
        value = row_dict(row, json_columns={"allocation_proof"})
        value["worker"] = {
            "id": row["worker_id"],
            "signing_public_key": row["worker_signing_public_key"],
            "encryption_public_key": row["worker_encryption_public_key"],
            "certificate": row["worker_certificate"],
        }
        for key in (
            "worker_signing_public_key",
            "worker_encryption_public_key",
            "worker_certificate",
        ):
            value.pop(key, None)
        return value

    def offer_worker(self, *, worker_id: str, owner_user_id: str, pool_id: str) -> dict[str, Any]:
        worker = self.db.fetchone(
            "SELECT * FROM workers WHERE id=? AND owner_user_id=? AND status!='revoked'",
            (worker_id, owner_user_id),
        )
        if worker is None:
            raise RepositoryError(FORBIDDEN, "WORKER_ACCESS_DENIED", "Worker access denied.", 403)
        pool = self.db.fetchone("SELECT * FROM pools WHERE id=? AND status='active'", (pool_id,))
        if pool is None:
            raise RepositoryError(POOL_NOT_FOUND, "POOL_NOT_FOUND", "Pool not found.", 404)
        allocation_id = new_id("alc")
        stamp = now()
        self.db.execute(
            """INSERT INTO worker_allocations
               (id,worker_id,workspace_id,pool_id,owner_consent_at,status,created_at,updated_at)
               VALUES (?,?,?,?,?,'pending_workspace',?,?)
               ON CONFLICT(worker_id,pool_id) DO UPDATE SET
                 owner_consent_at=excluded.owner_consent_at,workspace_approved_at=NULL,
                 approved_by_user_id=NULL,allocation_proof=NULL,status='pending_workspace',
                 updated_at=excluded.updated_at,revoked_at=NULL""",
            (allocation_id, worker_id, pool["workspace_id"], pool_id, stamp, stamp, stamp),
        )
        row = self.db.fetchone(
            "SELECT * FROM worker_allocations WHERE worker_id=? AND pool_id=?", (worker_id, pool_id)
        )
        return row_dict(row)

    def approve_allocation(
        self, *, allocation_id: str, admin_user_id: str, proof: dict[str, Any]
    ) -> dict[str, Any]:
        allocation = self.db.fetchone(
            """SELECT a.*,w.signing_public_key AS worker_signing_public_key,
                      w.encryption_public_key AS worker_encryption_public_key,
                      w.certificate AS worker_certificate
               FROM worker_allocations a JOIN workers w ON w.id=a.worker_id
               WHERE a.id=?""",
            (allocation_id,),
        )
        if allocation is None:
            raise RepositoryError(
                WORKER_ALLOCATION_NOT_FOUND,
                "WORKER_ALLOCATION_NOT_FOUND",
                "Worker allocation not found.",
                404,
            )
        self.require_admin(allocation["workspace_id"], admin_user_id)
        admin = self.require_user(admin_user_id)
        try:
            root_key = b64url_decode(admin["root_signing_public_key"], expected_length=32)
            payload = proof["payload"]
            expected = build_allocation_proof_payload(
                allocation_id=allocation["id"],
                workspace_id=allocation["workspace_id"],
                pool_id=allocation["pool_id"],
                worker_id=allocation["worker_id"],
                worker_signing_public_key=allocation["worker_signing_public_key"],
                worker_encryption_public_key=allocation["worker_encryption_public_key"],
                worker_certificate=allocation["worker_certificate"],
                owner_consent_at=float(allocation["owner_consent_at"]),
                approver_root_key_id=root_signing_key_id(root_key),
                issued_at=int(payload["issued_at"]),
            )
            valid = verify_allocation_proof(proof, root_key, expected=expected)
        except (KeyError, TypeError, ValueError):
            valid = False
        if not valid:
            raise RepositoryError(
                230004,
                "ALLOCATION_PROOF_INVALID",
                "The Workspace allocation proof is invalid.",
                422,
            )
        stamp = now()
        self.db.execute(
            """UPDATE worker_allocations
               SET workspace_approved_at=?,approved_by_user_id=?,allocation_proof=?,status='active',updated_at=?
               WHERE id=?""",
            (stamp, admin_user_id, json_text(proof), stamp, allocation_id),
        )
        return row_dict(
            self.db.fetchone("SELECT * FROM worker_allocations WHERE id=?", (allocation_id,)),
            json_columns={"allocation_proof"},
        )

    def worker_heartbeat(
        self, *, worker_id: str, capabilities: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        worker = self.db.fetchone("SELECT * FROM workers WHERE id=?", (worker_id,))
        if worker is None:
            raise RepositoryError(WORKER_NOT_FOUND, "WORKER_NOT_FOUND", "Worker not found.", 404)
        if worker["status"] == "revoked":
            raise RepositoryError(WORKER_REVOKED, "WORKER_REVOKED", "Worker has been revoked.", 403)
        if worker["status"] == "draining":
            stamp = now()
            self.db.execute(
                "UPDATE workers SET last_seen_at=?,updated_at=? WHERE id=?",
                (stamp, stamp, worker_id),
            )
            return {"ok": True, "status": "draining"}
        if not isinstance(capabilities, dict) or not capabilities:
            raise RepositoryError(
                VALIDATION_FAILED,
                "WORKER_CAPABILITIES_REQUIRED",
                "A healthy capability report is required.",
                422,
            )
        stamp = now()
        self.db.execute(
            "UPDATE workers SET status='active',last_seen_at=?,capabilities=?,updated_at=? WHERE id=?",
            (stamp, json_text(capabilities), stamp, worker_id),
        )
        return {"ok": True, "status": "active"}

    def leave_worker(self, *, worker_id: str, owner_user_id: str, force: bool) -> dict[str, Any]:
        worker = self.db.fetchone(
            "SELECT * FROM workers WHERE id=? AND owner_user_id=?", (worker_id, owner_user_id)
        )
        if worker is None:
            raise RepositoryError(FORBIDDEN, "WORKER_ACCESS_DENIED", "Worker access denied.", 403)
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            has_active_attempt = conn.execute(
                """SELECT 1 FROM task_attempts
                   WHERE worker_id=? AND state IN ('reserved','leased','running') LIMIT 1""",
                (worker_id,),
            ).fetchone()
            status = "revoked" if force or has_active_attempt is None else "draining"
            conn.execute(
                "UPDATE workers SET status=?,updated_at=?,revoked_at=CASE WHEN ? THEN ? ELSE revoked_at END WHERE id=?",
                (status, stamp, int(status == "revoked"), stamp, worker_id),
            )
            conn.execute(
                "UPDATE worker_allocations SET status='revoked',revoked_at=?,updated_at=? WHERE worker_id=? AND status!='revoked'",
                (stamp, stamp, worker_id),
            )
            # Leaving is also a revocation boundary for remote maintenance.
            # Fence queued and leased jobs before a revoked Worker session can
            # activate a staged runtime or publish another model file.
            conn.execute(
                """UPDATE worker_maintenance_jobs
                   SET state='cancelled',completed_at=?,updated_at=?,lease_session_id=NULL,
                       lease_expires_at=NULL,fencing_token=fencing_token+1
                   WHERE worker_id=?
                     AND state IN ('awaiting_upload','queued','leased','running','restarting')""",
                (stamp, stamp, worker_id),
            )
            if status == "revoked":
                conn.execute(
                    "UPDATE sessions SET revoked_at=? WHERE principal_type='worker' AND principal_id=? AND revoked_at IS NULL",
                    (stamp, worker_id),
                )
            if force:
                affected_tasks = conn.execute(
                    """SELECT id FROM tasks
                       WHERE assigned_worker_id=?
                         AND state IN ('committed','queued','reserved','running')""",
                    (worker_id,),
                ).fetchall()
                conn.execute(
                    "UPDATE leases SET released_at=? WHERE worker_id=? AND released_at IS NULL",
                    (stamp, worker_id),
                )
                conn.execute(
                    """UPDATE task_attempts SET state='cancelled',finished_at=?,responsibility='provider',failure_code=?
                       WHERE worker_id=? AND state IN ('reserved','leased','running')""",
                    (stamp, WORKER_OFFLINE, worker_id),
                )
                conn.execute(
                    """UPDATE tasks SET state='rekey_required',updated_at=?
                       WHERE assigned_worker_id=? AND state IN ('committed','queued','reserved','running')""",
                    (stamp, worker_id),
                )
                for task in affected_tasks:
                    attempt = conn.execute(
                        """SELECT id FROM task_attempts WHERE task_id=?
                           ORDER BY attempt_number DESC LIMIT 1""",
                        (task["id"],),
                    ).fetchone()
                    self._enqueue_task_rekey_command(
                        conn,
                        task_id=task["id"],
                        source_attempt_id=str(attempt["id"] if attempt else "none"),
                        reason="worker_revoked",
                        stamp=stamp,
                    )
        return {"worker_id": worker_id, "status": status, "force": force}

    # --------------------------------------------------------- worker maintenance

    @staticmethod
    def _maintenance_job_value(
        row: sqlite3.Row,
        *,
        include_authorization: bool = False,
    ) -> dict[str, Any]:
        value = row_dict(row, json_columns={"spec", "authorization", "progress", "result"})
        if not include_authorization:
            value.pop("authorization", None)
        value.pop("dedupe_key", None)
        value.pop("lease_session_id", None)
        return value

    def _maintenance_artifact_value(self, job_id: str) -> dict[str, Any] | None:
        row = self.db.fetchone(
            "SELECT * FROM maintenance_artifacts WHERE job_id=?", (job_id,)
        )
        return row_dict(row) if row is not None else None

    def _require_exact_broker_device(
        self,
        *,
        broker_id: str,
        user_id: str,
        device_id: str,
    ) -> sqlite3.Row:
        row = self.db.fetchone(
            """SELECT b.id AS broker_id,b.owner_user_id,bd.id AS broker_device_id,
                      bd.device_id
               FROM brokers b JOIN broker_devices bd ON bd.broker_id=b.id
               JOIN devices d ON d.id=bd.device_id
               WHERE b.id=? AND b.owner_user_id=? AND b.status='active'
                 AND bd.device_id=? AND bd.status='active'
                 AND d.user_id=? AND d.status='active'""",
            (broker_id, user_id, device_id, user_id),
        )
        if row is None:
            raise RepositoryError(
                FORBIDDEN,
                "BROKER_DEVICE_ACCESS_DENIED",
                "The authenticated Device is not an active Device of this Broker.",
                403,
            )
        return row

    def set_worker_manager(
        self,
        *,
        worker_id: str,
        owner_user_id: str,
        actor_device_id: str,
        broker_id: str | None,
    ) -> dict[str, Any]:
        self.require_user(owner_user_id)
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            worker = conn.execute(
                "SELECT * FROM workers WHERE id=? AND owner_user_id=? AND status!='revoked'",
                (worker_id, owner_user_id),
            ).fetchone()
            if worker is None:
                raise RepositoryError(
                    FORBIDDEN, "WORKER_ACCESS_DENIED", "Worker access denied.", 403
                )
            if broker_id is not None:
                broker = conn.execute(
                    """SELECT id FROM brokers
                       WHERE id=? AND owner_user_id=? AND status='active'""",
                    (broker_id, owner_user_id),
                ).fetchone()
                if broker is None:
                    raise RepositoryError(
                        FORBIDDEN,
                        "BROKER_ACCESS_DENIED",
                        "The manager Broker is not owned by the Worker owner.",
                        403,
                    )
            if worker["manager_broker_id"] == broker_id:
                return row_dict(worker, json_columns={"capabilities"})
            active = conn.execute(
                """SELECT 1 FROM worker_maintenance_jobs
                   WHERE worker_id=? AND state IN
                     ('awaiting_upload','queued','leased','running','restarting') LIMIT 1""",
                (worker_id,),
            ).fetchone()
            if active is not None:
                raise RepositoryError(
                    WORKER_MAINTENANCE_STATE_CONFLICT,
                    "WORKER_MAINTENANCE_STATE_CONFLICT",
                    "The manager Broker cannot change while maintenance is active.",
                    409,
                )
            conn.execute(
                "UPDATE workers SET manager_broker_id=?,updated_at=? WHERE id=?",
                (broker_id, stamp, worker_id),
            )
            conn.execute(
                """INSERT INTO audit_events
                   (id,actor_type,actor_id,action,subject_type,subject_id,safe_details,created_at)
                   VALUES (?, 'device',?,'worker.manager_changed','worker',?,?,?)""",
                (
                    new_id("aud"),
                    actor_device_id,
                    worker_id,
                    json_text(
                        {
                            "previous_broker_id": worker["manager_broker_id"],
                            "manager_broker_id": broker_id,
                        }
                    ),
                    stamp,
                ),
            )
        return row_dict(
            self.db.fetchone("SELECT * FROM workers WHERE id=?", (worker_id,)),
            json_columns={"capabilities"},
        )

    def create_worker_maintenance(
        self,
        *,
        broker_id: str,
        worker_id: str,
        user_id: str,
        device_id: str,
        kind: str,
        spec: dict[str, Any],
        spec_digest: str,
        authorization: dict[str, Any],
        expires_at: int,
        artifact_store_type: str,
    ) -> dict[str, Any]:
        self._require_exact_broker_device(
            broker_id=broker_id, user_id=user_id, device_id=device_id
        )
        worker = self.db.fetchone(
            """SELECT * FROM workers
               WHERE id=? AND owner_user_id=? AND manager_broker_id=? AND status!='revoked'""",
            (worker_id, user_id, broker_id),
        )
        if worker is None:
            raise RepositoryError(
                FORBIDDEN,
                "WORKER_MANAGER_BROKER_REQUIRED",
                "This Broker is not the Worker's delegated manager.",
                403,
            )
        if kind not in {"worker_update", "model_install"}:
            raise RepositoryError(
                VALIDATION_FAILED,
                "WORKER_MAINTENANCE_KIND_INVALID",
                "Worker maintenance kind is invalid.",
                422,
            )
        stamp = now()
        if expires_at <= stamp:
            raise RepositoryError(
                VALIDATION_FAILED,
                "WORKER_MAINTENANCE_AUTHORIZATION_EXPIRED",
                "Worker maintenance authorization has expired.",
                422,
            )
        dedupe_key = spec_digest
        with self.db.transaction(immediate=True) as conn:
            self._expire_maintenance_jobs(conn, stamp)
            existing = conn.execute(
                """SELECT * FROM worker_maintenance_jobs
                   WHERE worker_id=? AND dedupe_key=?
                     AND state IN ('awaiting_upload','queued','leased','running','restarting')""",
                (worker_id, dedupe_key),
            ).fetchone()
            if existing is not None:
                value = self._maintenance_job_value(existing)
                artifact = conn.execute(
                    "SELECT * FROM maintenance_artifacts WHERE job_id=?", (existing["id"],)
                ).fetchone()
                if artifact is not None:
                    value["artifact"] = row_dict(artifact)
                    value["artifact_id"] = artifact["id"]
                return value

            job_id = new_id("mtj")
            state = "awaiting_upload" if kind == "worker_update" else "queued"
            conn.execute(
                """INSERT INTO worker_maintenance_jobs
                   (id,worker_id,broker_id,issued_by_user_id,issued_by_device_id,kind,spec,
                    spec_digest,authorization,dedupe_key,state,expires_at,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id,
                    worker_id,
                    broker_id,
                    user_id,
                    device_id,
                    kind,
                    json_text(spec),
                    spec_digest,
                    json_text(authorization),
                    dedupe_key,
                    state,
                    float(expires_at),
                    stamp,
                    stamp,
                ),
            )
            artifact_id: str | None = None
            if kind == "worker_update":
                artifact_id = new_id("art")
                conn.execute(
                    """INSERT INTO maintenance_artifacts
                       (id,job_id,kind,store_type,object_ref,expected_size,expected_sha256,
                        state,created_at,updated_at)
                       VALUES (?,?,'worker_update',?,?,?,?, 'pending',?,?)""",
                    (
                        artifact_id,
                        job_id,
                        artifact_store_type,
                        artifact_id,
                        int(spec["artifact_size"]),
                        str(spec["artifact_sha256"]),
                        stamp,
                        stamp,
                    ),
                )
            conn.execute(
                """INSERT INTO audit_events
                   (id,actor_type,actor_id,action,subject_type,subject_id,safe_details,created_at)
                   VALUES (?, 'device',?,'worker.maintenance_created',
                           'worker_maintenance_job',?,?,?)""",
                (
                    new_id("aud"),
                    device_id,
                    job_id,
                    json_text(
                        {
                            "worker_id": worker_id,
                            "broker_id": broker_id,
                            "kind": kind,
                            "spec_digest": spec_digest,
                            "artifact_id": artifact_id,
                        }
                    ),
                    stamp,
                ),
            )
            created = conn.execute(
                "SELECT * FROM worker_maintenance_jobs WHERE id=?", (job_id,)
            ).fetchone()
            value = self._maintenance_job_value(created)
            if artifact_id is not None:
                artifact = conn.execute(
                    "SELECT * FROM maintenance_artifacts WHERE id=?", (artifact_id,)
                ).fetchone()
                value["artifact"] = row_dict(artifact)
                value["artifact_id"] = artifact_id
            return value

    def _require_broker_maintenance_job(
        self,
        *,
        job_id: str,
        user_id: str,
        device_id: str,
    ) -> sqlite3.Row:
        job = self.db.fetchone(
            "SELECT * FROM worker_maintenance_jobs WHERE id=?", (job_id,)
        )
        if job is None:
            raise RepositoryError(
                WORKER_MAINTENANCE_JOB_NOT_FOUND,
                "WORKER_MAINTENANCE_JOB_NOT_FOUND",
                "Worker maintenance job not found.",
                404,
            )
        self._require_exact_broker_device(
            broker_id=job["broker_id"], user_id=user_id, device_id=device_id
        )
        worker = self.db.fetchone(
            """SELECT id FROM workers
               WHERE id=? AND owner_user_id=? AND manager_broker_id=? AND status!='revoked'""",
            (job["worker_id"], user_id, job["broker_id"]),
        )
        if worker is None:
            raise RepositoryError(
                FORBIDDEN,
                "WORKER_MANAGER_BROKER_REQUIRED",
                "This Broker is no longer the Worker's delegated manager.",
                403,
            )
        return job

    def maintenance_artifact_for_commit(
        self, *, job_id: str, user_id: str, device_id: str
    ) -> dict[str, Any]:
        job = self._require_broker_maintenance_job(
            job_id=job_id, user_id=user_id, device_id=device_id
        )
        artifact = self.db.fetchone(
            "SELECT * FROM maintenance_artifacts WHERE job_id=?", (job["id"],)
        )
        if artifact is None:
            raise RepositoryError(
                WORKER_MAINTENANCE_STATE_CONFLICT,
                "WORKER_MAINTENANCE_STATE_CONFLICT",
                "This maintenance job has no upload artifact.",
                409,
            )
        return row_dict(artifact)

    def commit_worker_maintenance(
        self, *, job_id: str, user_id: str, device_id: str
    ) -> dict[str, Any]:
        self._require_broker_maintenance_job(
            job_id=job_id, user_id=user_id, device_id=device_id
        )
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            self._expire_maintenance_jobs(conn, stamp)
            job = conn.execute(
                "SELECT * FROM worker_maintenance_jobs WHERE id=?", (job_id,)
            ).fetchone()
            if job["state"] == "queued":
                return self._maintenance_job_value(job)
            if job["state"] != "awaiting_upload":
                raise RepositoryError(
                    WORKER_MAINTENANCE_STATE_CONFLICT,
                    "WORKER_MAINTENANCE_STATE_CONFLICT",
                    "Worker maintenance cannot be committed from its current state.",
                    409,
                )
            artifact = conn.execute(
                "SELECT * FROM maintenance_artifacts WHERE job_id=?", (job_id,)
            ).fetchone()
            if artifact is None or artifact["state"] != "uploaded":
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "MAINTENANCE_ARTIFACT_NOT_UPLOADED",
                    "The Worker update artifact has not been uploaded and verified.",
                    409,
                )
            conn.execute(
                "UPDATE worker_maintenance_jobs SET state='queued',updated_at=? WHERE id=?",
                (stamp, job_id),
            )
            conn.execute(
                """INSERT INTO audit_events
                   (id,actor_type,actor_id,action,subject_type,subject_id,safe_details,created_at)
                   VALUES (?, 'device',?,'worker.maintenance_committed',
                           'worker_maintenance_job',?,'{}',?)""",
                (new_id("aud"), device_id, job_id, stamp),
            )
            job = conn.execute(
                "SELECT * FROM worker_maintenance_jobs WHERE id=?", (job_id,)
            ).fetchone()
        return self._maintenance_job_value(job)

    def list_worker_maintenance(
        self, *, worker_id: str, owner_user_id: str, limit: int
    ) -> list[dict[str, Any]]:
        worker = self.db.fetchone(
            "SELECT id FROM workers WHERE id=? AND owner_user_id=?",
            (worker_id, owner_user_id),
        )
        if worker is None:
            raise RepositoryError(
                FORBIDDEN, "WORKER_ACCESS_DENIED", "Worker access denied.", 403
            )
        return [
            self._maintenance_job_value(row)
            for row in self.db.fetchall(
                """SELECT * FROM worker_maintenance_jobs WHERE worker_id=?
                   ORDER BY created_at DESC LIMIT ?""",
                (worker_id, min(max(limit, 1), 500)),
            )
        ]

    def get_worker_maintenance(self, *, job_id: str, owner_user_id: str) -> dict[str, Any]:
        row = self.db.fetchone(
            """SELECT j.* FROM worker_maintenance_jobs j JOIN workers w ON w.id=j.worker_id
               WHERE j.id=? AND w.owner_user_id=?""",
            (job_id, owner_user_id),
        )
        if row is None:
            raise RepositoryError(
                WORKER_MAINTENANCE_JOB_NOT_FOUND,
                "WORKER_MAINTENANCE_JOB_NOT_FOUND",
                "Worker maintenance job not found.",
                404,
            )
        value = self._maintenance_job_value(row)
        artifact = self._maintenance_artifact_value(job_id)
        if artifact is not None:
            value["artifact"] = artifact
            value["artifact_id"] = artifact["id"]
        return value

    def cancel_worker_maintenance(
        self,
        *,
        job_id: str,
        owner_user_id: str,
        actor_device_id: str,
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute(
                """SELECT j.* FROM worker_maintenance_jobs j
                   JOIN workers w ON w.id=j.worker_id
                   WHERE j.id=? AND w.owner_user_id=?""",
                (job_id, owner_user_id),
            ).fetchone()
            if row is None:
                raise RepositoryError(
                    WORKER_MAINTENANCE_JOB_NOT_FOUND,
                    "WORKER_MAINTENANCE_JOB_NOT_FOUND",
                    "Worker maintenance job not found.",
                    404,
                )
            if row["state"] == "cancelled":
                return self._maintenance_job_value(row)
            if row["state"] in {"succeeded", "failed", "expired"}:
                raise RepositoryError(
                    WORKER_MAINTENANCE_STATE_CONFLICT,
                    "WORKER_MAINTENANCE_STATE_CONFLICT",
                    "A completed maintenance job cannot be cancelled.",
                    409,
                )
            conn.execute(
                """UPDATE worker_maintenance_jobs
                   SET state='cancelled',completed_at=?,updated_at=?,lease_expires_at=NULL
                   WHERE id=?""",
                (stamp, stamp, job_id),
            )
            conn.execute(
                """INSERT INTO audit_events
                   (id,actor_type,actor_id,action,subject_type,subject_id,safe_details,created_at)
                   VALUES (?, 'device',?,'worker.maintenance_cancelled',
                           'worker_maintenance_job',?,'{}',?)""",
                (new_id("aud"), actor_device_id, job_id, stamp),
            )
            row = conn.execute(
                "SELECT * FROM worker_maintenance_jobs WHERE id=?", (job_id,)
            ).fetchone()
        return self._maintenance_job_value(row)

    def claim_worker_maintenance(
        self,
        *,
        worker_id: str,
        session_id: str,
        ttl_seconds: int,
    ) -> dict[str, Any] | None:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            self._expire_reservations(conn, stamp)
            self._expire_leases(conn, stamp)
            self._expire_maintenance_jobs(conn, stamp)
            worker = conn.execute("SELECT * FROM workers WHERE id=?", (worker_id,)).fetchone()
            if worker is None:
                raise RepositoryError(
                    WORKER_NOT_FOUND, "WORKER_NOT_FOUND", "Worker not found.", 404
                )
            if worker["status"] == "draining":
                raise RepositoryError(
                    WORKER_DRAINING, "WORKER_DRAINING", "Worker is draining.", 409
                )
            if worker["status"] != "active":
                raise RepositoryError(
                    WORKER_OFFLINE,
                    "WORKER_OFFLINE",
                    "Worker is not active.",
                    409,
                    "later",
                )
            existing = conn.execute(
                """SELECT * FROM worker_maintenance_jobs
                   WHERE worker_id=? AND state IN ('leased','running','restarting')
                     AND lease_expires_at>? ORDER BY created_at LIMIT 1""",
                (worker_id, stamp),
            ).fetchone()
            if existing is not None:
                if existing["lease_session_id"] != session_id:
                    return None
                lease_expires_at = min(stamp + ttl_seconds, float(existing["expires_at"]))
                conn.execute(
                    """UPDATE worker_maintenance_jobs
                       SET lease_expires_at=?,heartbeat_at=?,updated_at=? WHERE id=?""",
                    (lease_expires_at, stamp, stamp, existing["id"]),
                )
                existing = conn.execute(
                    "SELECT * FROM worker_maintenance_jobs WHERE id=?", (existing["id"],)
                ).fetchone()
                return self._maintenance_job_with_artifact(existing, include_authorization=True)
            active_attempt = conn.execute(
                """SELECT 1 FROM task_attempts
                   WHERE worker_id=? AND state IN ('leased','running') LIMIT 1""",
                (worker_id,),
            ).fetchone()
            if active_attempt is not None:
                return None
            job = conn.execute(
                """SELECT * FROM worker_maintenance_jobs
                   WHERE worker_id=? AND state='queued' AND expires_at>?
                   ORDER BY created_at LIMIT 1""",
                (worker_id, stamp),
            ).fetchone()
            if job is None:
                return None
            fencing_token = int(job["fencing_token"]) + 1
            lease_expires_at = min(stamp + ttl_seconds, float(job["expires_at"]))
            conn.execute(
                """UPDATE worker_maintenance_jobs
                   SET state='leased',fencing_token=?,lease_session_id=?,lease_expires_at=?,
                       heartbeat_at=?,updated_at=? WHERE id=? AND state='queued'""",
                (
                    fencing_token,
                    session_id,
                    lease_expires_at,
                    stamp,
                    stamp,
                    job["id"],
                ),
            )
            job = conn.execute(
                "SELECT * FROM worker_maintenance_jobs WHERE id=?", (job["id"],)
            ).fetchone()
            return self._maintenance_job_with_artifact(job, include_authorization=True)

    def _maintenance_job_with_artifact(
        self, row: sqlite3.Row, *, include_authorization: bool
    ) -> dict[str, Any]:
        value = self._maintenance_job_value(row, include_authorization=include_authorization)
        artifact = self.db.fetchone(
            "SELECT * FROM maintenance_artifacts WHERE job_id=?", (row["id"],)
        )
        if artifact is not None:
            value["artifact"] = row_dict(artifact)
            value["artifact_id"] = artifact["id"]
        return value

    def active_worker_maintenance_lease(
        self,
        *,
        job_id: str,
        worker_id: str,
        session_id: str,
        fencing_token: int,
    ) -> dict[str, Any] | None:
        stamp = now()
        row = self.db.fetchone(
            """SELECT * FROM worker_maintenance_jobs
               WHERE id=? AND worker_id=? AND lease_session_id=? AND fencing_token=?
                 AND state IN ('leased','running','restarting') AND lease_expires_at>?""",
            (job_id, worker_id, session_id, fencing_token, stamp),
        )
        if row is None:
            return None
        return self._maintenance_job_with_artifact(row, include_authorization=True)

    def heartbeat_worker_maintenance(
        self,
        *,
        job_id: str,
        worker_id: str,
        session_id: str,
        fencing_token: int,
        ttl_seconds: int,
        state: str,
        progress: dict[str, Any] | None,
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute(
                """SELECT * FROM worker_maintenance_jobs
                   WHERE id=? AND worker_id=? AND fencing_token=?""",
                (job_id, worker_id, fencing_token),
            ).fetchone()
            if row is not None and row["state"] == "cancelled":
                return {"ok": True, "cancelled": True, "state": "cancelled"}
            if (
                row is None
                or row["lease_session_id"] != session_id
                or row["state"] not in _MAINTENANCE_LEASE_STATES
                or float(row["lease_expires_at"] or 0) <= stamp
                or float(row["expires_at"] or 0) <= stamp
            ):
                raise RepositoryError(
                    MAINTENANCE_LEASE_LOST,
                    "MAINTENANCE_LEASE_LOST",
                    "Worker maintenance lease is no longer valid.",
                    409,
                    "later",
                    "platform",
                )
            lease_expires_at = min(stamp + ttl_seconds, float(row["expires_at"]))
            conn.execute(
                """UPDATE worker_maintenance_jobs
                   SET state=?,progress=?,heartbeat_at=?,lease_expires_at=?,updated_at=?
                   WHERE id=?""",
                (
                    state,
                    json_text(progress or {}),
                    stamp,
                    lease_expires_at,
                    stamp,
                    job_id,
                ),
            )
        return {
            "ok": True,
            "cancelled": False,
            "state": state,
            "lease_expires_at": lease_expires_at,
        }

    def complete_worker_maintenance(
        self,
        *,
        job_id: str,
        worker_id: str,
        session_id: str,
        fencing_token: int,
        succeeded: bool,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute(
                """SELECT * FROM worker_maintenance_jobs
                   WHERE id=? AND worker_id=? AND fencing_token=?""",
                (job_id, worker_id, fencing_token),
            ).fetchone()
            if row is not None and row["state"] in {"succeeded", "failed"}:
                stored_result = json.loads(row["result"] or "{}")
                expected_state = "succeeded" if succeeded else "failed"
                if row["state"] == expected_state and stored_result == result:
                    # The DB commit can succeed before the HTTP idempotency
                    # recipe is persisted.  An identical retry must be able to
                    # confirm activation and clear the Worker's pending pointer.
                    return self._maintenance_job_value(row)
                raise RepositoryError(
                    WORKER_MAINTENANCE_STATE_CONFLICT,
                    "WORKER_MAINTENANCE_STATE_CONFLICT",
                    "Worker maintenance was already completed with a different result.",
                    409,
                )
            if (
                row is None
                or row["lease_session_id"] != session_id
                or row["state"] not in _MAINTENANCE_LEASE_STATES
                or float(row["lease_expires_at"] or 0) <= stamp
                or float(row["expires_at"] or 0) <= stamp
            ):
                raise RepositoryError(
                    MAINTENANCE_LEASE_LOST,
                    "MAINTENANCE_LEASE_LOST",
                    "Worker maintenance lease is no longer valid.",
                    409,
                    "later",
                    "platform",
                )
            spec = json.loads(row["spec"])
            if result.get("kind") != row["kind"]:
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "WORKER_MAINTENANCE_RESULT_INVALID",
                    "Worker maintenance result kind does not match the job.",
                    422,
                )
            status = result.get("status")
            if row["kind"] == "worker_update":
                valid = (
                    result.get("target_version") == spec.get("target_version")
                    and result.get("artifact_sha256") == spec.get("artifact_sha256")
                    and succeeded == (status == "activated")
                )
            else:
                requested = set(spec.get("model_digests", []))
                installed = set(result.get("installed_model_digests", []))
                failed_digest = result.get("failed_model_digest")
                valid = (
                    installed <= requested
                    and (failed_digest is None or failed_digest in requested)
                    and succeeded == (status in {"installed", "already_installed"})
                    and (not succeeded or installed == requested)
                )
            if not valid:
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "WORKER_MAINTENANCE_RESULT_INVALID",
                    "Worker maintenance result does not match the authorized specification.",
                    422,
                )
            final_state = "succeeded" if succeeded else "failed"
            conn.execute(
                """UPDATE worker_maintenance_jobs
                   SET state=?,result=?,completed_at=?,updated_at=?,lease_expires_at=NULL
                   WHERE id=?""",
                (final_state, json_text(result), stamp, stamp, job_id),
            )
            if succeeded and row["kind"] == "worker_update":
                conn.execute(
                    """UPDATE maintenance_artifacts SET state='available',updated_at=?
                       WHERE job_id=? AND state='uploaded'""",
                    (stamp, job_id),
                )
            conn.execute(
                """INSERT INTO audit_events
                   (id,actor_type,actor_id,action,subject_type,subject_id,safe_details,created_at)
                   VALUES (?, 'worker',?,'worker.maintenance_completed',
                           'worker_maintenance_job',?,?,?)""",
                (
                    new_id("aud"),
                    worker_id,
                    job_id,
                    json_text(
                        {"kind": row["kind"], "status": status, "succeeded": succeeded}
                    ),
                    stamp,
                ),
            )
            row = conn.execute(
                "SELECT * FROM worker_maintenance_jobs WHERE id=?", (job_id,)
            ).fetchone()
        return self._maintenance_job_value(row)

    # --------------------------------------------------------------------- rates

    def propose_rate(
        self,
        *,
        worker_id: str,
        workspace_id: str,
        user_id: str,
        rate_microtokens_per_gpu_second: int,
        traffic_microtokens_per_gib: int,
    ) -> dict[str, Any]:
        worker = self.db.fetchone("SELECT * FROM workers WHERE id=?", (worker_id,))
        if worker is None:
            raise RepositoryError(WORKER_NOT_FOUND, "WORKER_NOT_FOUND", "Worker not found.", 404)
        if worker["owner_user_id"] != user_id:
            raise RepositoryError(
                FORBIDDEN,
                "WORKER_ACCESS_DENIED",
                "Only the worker owner can propose its rate.",
                403,
            )
        rate_id = new_id("rat")
        self.db.execute(
            """INSERT INTO rate_cards
               (id,worker_id,workspace_id,proposed_by_user_id,rate_microtokens_per_gpu_second,
                traffic_microtokens_per_gib,status,proposed_at)
               VALUES (?,?,?,?,?,?,'proposed',?)""",
            (
                rate_id,
                worker_id,
                workspace_id,
                user_id,
                rate_microtokens_per_gpu_second,
                traffic_microtokens_per_gib,
                now(),
            ),
        )
        return row_dict(self.db.fetchone("SELECT * FROM rate_cards WHERE id=?", (rate_id,)))

    def approve_rate(self, *, rate_id: str, admin_user_id: str) -> dict[str, Any]:
        rate = self.db.fetchone("SELECT * FROM rate_cards WHERE id=?", (rate_id,))
        if rate is None:
            raise RepositoryError(RATE_NOT_FOUND, "RATE_NOT_FOUND", "Rate card not found.", 404)
        self.require_admin(rate["workspace_id"], admin_user_id)
        if int(rate["traffic_microtokens_per_gib"]) != 0:
            raise RepositoryError(
                RATE_NOT_APPROVED,
                "TRAFFIC_BILLING_NOT_ENABLED",
                "Traffic billing is not enabled by the v1 rate policy.",
                409,
            )
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            conn.execute(
                """UPDATE rate_cards SET status='superseded'
                   WHERE worker_id=? AND workspace_id=? AND status='approved'""",
                (rate["worker_id"], rate["workspace_id"]),
            )
            conn.execute(
                "UPDATE rate_cards SET status='approved',approved_by_user_id=?,decided_at=? WHERE id=?",
                (admin_user_id, stamp, rate_id),
            )
        return row_dict(self.db.fetchone("SELECT * FROM rate_cards WHERE id=?", (rate_id,)))

    # -------------------------------------------------------------- tasks/leases

    def _allocation_security_view(self, worker_row: sqlite3.Row) -> dict[str, Any]:
        """Return the immutable approval proof and its Workspace-admin trust key."""

        try:
            proof = json.loads(worker_row["allocation_proof"])
            approver_id = worker_row["allocation_approved_by"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RepositoryError(
                230004,
                "ALLOCATION_PROOF_INVALID",
                "The selected Worker allocation has no valid approval proof.",
                422,
            ) from exc
        approver = self.db.fetchone(
            "SELECT root_signing_public_key FROM users WHERE id=? AND status='active'",
            (approver_id,),
        )
        if approver is None:
            raise RepositoryError(
                230004,
                "ALLOCATION_PROOF_INVALID",
                "The allocation proof signer is no longer active.",
                422,
            )
        return {
            "id": worker_row["allocation_id"],
            "owner_consent_at": worker_row["allocation_owner_consent_at"],
            "proof": proof,
            "admin_user_id": approver_id,
            "admin_root_signing_public_key": approver["root_signing_public_key"],
        }

    def reserve_input_artifacts(
        self,
        *,
        task_id: str,
        artifacts: list[dict[str, Any]],
        store_type: str = "local",
    ) -> list[dict[str, Any]]:
        stamp = now()
        values: list[dict[str, Any]] = []
        canonical_artifacts = [
            {
                **descriptor,
                "media_metadata": self._artifact_media_metadata(
                    descriptor.get("media_metadata", {})
                ),
            }
            for descriptor in artifacts
        ]
        with self.db.transaction(immediate=True) as conn:
            task = conn.execute(
                "SELECT id FROM tasks WHERE id=? AND state='prepared'", (task_id,)
            ).fetchone()
            if task is None:
                raise RepositoryError(
                    TASK_STATE_CONFLICT, "TASK_STATE_CONFLICT", "Task is not prepared.", 409
                )
            for descriptor in canonical_artifacts:
                artifact_id = new_id("art")
                conn.execute(
                    """INSERT INTO artifacts
                       (id,task_id,kind,direction,store_type,object_ref,encrypted_size,media_metadata,state,created_at,updated_at)
                       VALUES (?,?,?,'input',?,?,?,?,'pending',?,?)""",
                    (
                        artifact_id,
                        task_id,
                        descriptor["kind"],
                        store_type,
                        artifact_id,
                        descriptor["encrypted_size"],
                        json_text(descriptor.get("media_metadata", {})),
                        stamp,
                        stamp,
                    ),
                )
                values.append(
                    row_dict(
                        conn.execute(
                            "SELECT * FROM artifacts WHERE id=?", (artifact_id,)
                        ).fetchone(),
                        json_columns={"media_metadata"},
                    )
                )
        return values

    def reserve_output_artifacts(
        self,
        *,
        task_id: str,
        attempt_id: str,
        count: int = 1,
        store_type: str = "local",
    ) -> list[dict[str, Any]]:
        count = min(max(int(count), 1), 8)
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            existing = conn.execute(
                """SELECT * FROM artifacts WHERE attempt_id=? AND direction='output'
                   AND state IN ('pending','uploaded') ORDER BY created_at""",
                (attempt_id,),
            ).fetchall()
            for index in range(len(existing), count):
                artifact_id = new_id("art")
                conn.execute(
                    """INSERT INTO artifacts
                       (id,task_id,attempt_id,kind,direction,store_type,object_ref,media_metadata,state,created_at,updated_at)
                       VALUES (?,?,?,?,'output',?,?, '{}','pending',?,?)""",
                    (
                        artifact_id,
                        task_id,
                        attempt_id,
                        f"output_{index}",
                        store_type,
                        artifact_id,
                        stamp,
                        stamp,
                    ),
                )
        return [
            row_dict(row, json_columns={"media_metadata"})
            for row in self.db.fetchall(
                """SELECT * FROM artifacts WHERE attempt_id=? AND direction='output'
                   AND state IN ('pending','uploaded') ORDER BY created_at LIMIT ?""",
                (attempt_id, count),
            )
        ]

    def refresh_output_artifacts(self, *, attempt_id: str, worker_id: str) -> list[dict[str, Any]]:
        lease = self.db.fetchone(
            """SELECT l.* FROM leases l JOIN task_attempts a ON a.id=l.attempt_id
               WHERE l.attempt_id=? AND l.worker_id=? AND l.released_at IS NULL AND l.expires_at>?""",
            (attempt_id, worker_id, now()),
        )
        if lease is None:
            raise RepositoryError(LEASE_LOST, "LEASE_LOST", "Lease is no longer valid.", 409)
        return [
            row_dict(row, json_columns={"media_metadata"})
            for row in self.db.fetchall(
                """SELECT * FROM artifacts WHERE attempt_id=? AND direction='output' AND state='pending'
                   ORDER BY created_at""",
                (attempt_id,),
            )
        ]

    def mark_artifact_uploaded(
        self, *, artifact_id: str, size: int, digest: str | None
    ) -> dict[str, Any]:
        cursor = self.db.execute(
            """UPDATE artifacts SET state='uploaded',encrypted_size=?,content_digest=?,updated_at=?
               WHERE id=? AND state IN ('pending','uploaded')""",
            (size, None if digest is None else "sha256:" + digest, now(), artifact_id),
        )
        if cursor.rowcount == 1:
            return row_dict(
                self.db.fetchone("SELECT * FROM artifacts WHERE id=?", (artifact_id,)),
                json_columns={"media_metadata"},
            )
        maintenance = self.db.fetchone(
            """SELECT ma.*,j.spec AS job_spec FROM maintenance_artifacts ma
               JOIN worker_maintenance_jobs j ON j.id=ma.job_id WHERE ma.id=?""",
            (artifact_id,),
        )
        if maintenance is None or maintenance["state"] not in ("pending", "uploaded"):
            raise RepositoryError(330003, "ARTIFACT_NOT_FOUND", "Artifact not found.", 404)
        digest_matches = digest is None or secrets.compare_digest(
            str(digest), str(maintenance["expected_sha256"])
        )
        if size != int(maintenance["expected_size"]) or not digest_matches:
            stamp = now()
            job_spec = json.loads(maintenance["job_spec"])
            with self.db.transaction(immediate=True) as conn:
                conn.execute(
                    """UPDATE maintenance_artifacts
                       SET state='failed',observed_size=?,observed_sha256=?,updated_at=?
                       WHERE id=?""",
                    (size, digest, stamp, artifact_id),
                )
                conn.execute(
                    """UPDATE worker_maintenance_jobs
                       SET state='failed',result=?,completed_at=?,updated_at=?
                       WHERE id=? AND state='awaiting_upload'""",
                    (
                        json_text(
                            {
                                "kind": "worker_update",
                                "status": "failed",
                                "target_version": job_spec["target_version"],
                                "artifact_sha256": job_spec["artifact_sha256"],
                                "error_code": int(ErrorCode.ARTIFACT_INTEGRITY_FAILED),
                            }
                        ),
                        stamp,
                        stamp,
                        maintenance["job_id"],
                    ),
                )
            raise RepositoryError(
                int(ErrorCode.ARTIFACT_INTEGRITY_FAILED),
                "ARTIFACT_INTEGRITY_FAILED",
                "Worker update artifact integrity verification failed.",
                422,
            )
        stamp = now()
        self.db.execute(
            """UPDATE maintenance_artifacts
               SET state='uploaded',observed_size=?,observed_sha256=?,updated_at=?
               WHERE id=? AND state IN ('pending','uploaded')""",
            (size, digest, stamp, artifact_id),
        )
        return row_dict(
            self.db.fetchone("SELECT * FROM maintenance_artifacts WHERE id=?", (artifact_id,))
        )

    def preflight_task(
        self,
        *,
        user_id: str | None,
        principal_type: str,
        principal_id: str,
        workspace_id: str,
        pool_id: str,
        executor_type: str,
        public_requirements: dict[str, Any],
    ) -> dict[str, Any]:
        """Report aggregate scheduling readiness without reserving any capacity."""

        public_requirements = self._public_requirements(public_requirements)
        if principal_type == "service":
            self.require_service(workspace_id, principal_id)
            if user_id is not None:
                raise RepositoryError(
                    FORBIDDEN,
                    "SERVICE_PRINCIPAL_INVALID",
                    "Service sessions cannot impersonate users.",
                    403,
                )
        else:
            self.require_member(workspace_id, user_id)
        workspace = self.db.fetchone(
            "SELECT 1 FROM workspaces WHERE id=? AND status='active'", (workspace_id,)
        )
        if workspace is None:
            raise RepositoryError(
                WORKSPACE_NOT_FOUND, "WORKSPACE_NOT_FOUND", "Workspace not found.", 404
            )
        pool = self.db.fetchone(
            "SELECT 1 FROM pools WHERE id=? AND workspace_id=? AND status='active'",
            (pool_id, workspace_id),
        )
        if pool is None:
            raise RepositoryError(POOL_NOT_FOUND, "POOL_NOT_FOUND", "Pool not found.", 404)

        def result(state: str, reason: str) -> dict[str, Any]:
            return {
                "ready": state == "ready",
                "state": state,
                "reason": reason,
                "workspace_id": workspace_id,
                "pool_id": pool_id,
                "executor_type": executor_type,
            }

        authorized = self.db.fetchone(
            """SELECT 1 FROM worker_allocations a JOIN workers w ON w.id=a.worker_id
               WHERE a.pool_id=? AND a.status='active' AND a.allocation_proof IS NOT NULL
               LIMIT 1""",
            (pool_id,),
        )
        if authorized is None:
            return result(
                "no_allocated_worker",
                "No authorized Worker is allocated to this Pool.",
            )

        stamp = now()
        candidate_rows = self._task_candidate_rows(
            self.db,
            pool_id=pool_id,
            executor_type=executor_type,
            stamp=stamp,
        )
        if not candidate_rows:
            if self._has_available_allocated_worker(
                self.db,
                pool_id=pool_id,
                stamp=stamp,
            ):
                return result(
                    "capability_mismatch",
                    "Available Workers do not provide the requested Executor.",
                )
            return result(
                "worker_offline_or_busy",
                "Allocated Workers are offline, draining, in maintenance, or at capacity.",
            )

        candidate = next(
            (row for row in candidate_rows if self._matches_requirements(row, public_requirements)),
            None,
        )
        if candidate is None:
            return result(
                "capability_mismatch",
                "Available Workers do not satisfy the public workflow requirements.",
            )
        rate = self.db.fetchone(
            """SELECT 1 FROM rate_cards
               WHERE worker_id=? AND workspace_id=? AND status='approved'
               ORDER BY decided_at DESC LIMIT 1""",
            (candidate["id"], workspace_id),
        )
        if rate is None:
            return result(
                "rate_not_approved",
                "The matching Worker has no approved rate for this Workspace.",
            )
        return result(
            "ready",
            "A matching Worker and approved rate are currently available.",
        )

    def prepare_task(
        self,
        *,
        user_id: str | None,
        principal_type: str,
        principal_id: str,
        client_channel: str,
        workspace_id: str,
        pool_id: str,
        workflow_ref: str,
        workflow_digest: str,
        executor_type: str,
        public_requirements: dict[str, Any],
        priority: int,
        reservation_ttl_seconds: int,
    ) -> dict[str, Any]:
        public_requirements = self._public_requirements(public_requirements)
        if principal_type == "service":
            self.require_service(workspace_id, principal_id)
            if user_id is not None:
                raise RepositoryError(
                    FORBIDDEN,
                    "SERVICE_PRINCIPAL_INVALID",
                    "Service sessions cannot impersonate users.",
                    403,
                )
        else:
            self.require_member(workspace_id, user_id)
        workspace = self.db.fetchone(
            "SELECT key_version FROM workspaces WHERE id=? AND status='active'", (workspace_id,)
        )
        if workspace is None:
            raise RepositoryError(
                WORKSPACE_NOT_FOUND, "WORKSPACE_NOT_FOUND", "Workspace not found.", 404
            )
        content_key_version = int(workspace["key_version"])
        pool = self.db.fetchone(
            "SELECT * FROM pools WHERE id=? AND workspace_id=? AND status='active'",
            (pool_id, workspace_id),
        )
        if pool is None:
            raise RepositoryError(POOL_NOT_FOUND, "POOL_NOT_FOUND", "Pool not found.", 404)
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            self._expire_reservations(conn, stamp)
            self._expire_leases(conn, stamp)
            candidate_rows = self._task_candidate_rows(
                conn,
                pool_id=pool_id,
                executor_type=executor_type,
                stamp=stamp,
            )
            candidates = next(
                (
                    row
                    for row in candidate_rows
                    if self._matches_requirements(row, public_requirements)
                ),
                None,
            )
            if candidates is None:
                raise RepositoryError(
                    NO_ELIGIBLE_WORKER,
                    "NO_ELIGIBLE_WORKER",
                    "No eligible worker is currently available.",
                    503,
                    "later",
                    "platform",
                    {"pool_id": pool_id, "executor_type": executor_type},
                )
            rate = conn.execute(
                """SELECT * FROM rate_cards
                   WHERE worker_id=? AND workspace_id=? AND status='approved'
                   ORDER BY decided_at DESC LIMIT 1""",
                (candidates["id"], workspace_id),
            ).fetchone()
            if rate is None:
                raise RepositoryError(
                    RATE_NOT_APPROVED,
                    "RATE_NOT_APPROVED",
                    "The selected worker has no approved rate.",
                    409,
                )
            task_id = new_id("tsk")
            attempt_id = new_id("atm")
            fencing = int(candidates["fencing_counter"]) + 1
            rate_snapshot = {
                "rate_card_id": rate["id"],
                "rate_microtokens_per_gpu_second": rate["rate_microtokens_per_gpu_second"],
                "traffic_microtokens_per_gib": rate["traffic_microtokens_per_gib"],
                "workflow_multiplier_ppm": 1_000_000,
                "formula_version": rate["formula_version"],
            }
            conn.execute(
                """INSERT INTO tasks
                   (id,workspace_id,pool_id,consumer_user_id,consumer_principal_type,consumer_principal_id,
                    client_channel,workflow_ref,workflow_digest,executor_type,public_requirements,content_key_version,
                    assigned_worker_id,reservation_expires_at,state,priority,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'prepared',?,?,?)""",
                (
                    task_id,
                    workspace_id,
                    pool_id,
                    user_id,
                    principal_type,
                    principal_id,
                    client_channel,
                    workflow_ref,
                    workflow_digest,
                    executor_type,
                    json_text(public_requirements),
                    content_key_version,
                    candidates["id"],
                    stamp + reservation_ttl_seconds,
                    priority,
                    stamp,
                    stamp,
                ),
            )
            conn.execute(
                "UPDATE workers SET fencing_counter=?,updated_at=? WHERE id=?",
                (fencing, stamp, candidates["id"]),
            )
            conn.execute(
                """INSERT INTO task_attempts
                   (id,task_id,attempt_number,worker_id,provider_user_id,manager_broker_id,executor_type,
                    executor_version,state,rate_snapshot,fencing_token,reserved_at)
                   VALUES (?,?,1,?,?,?,?,?,'reserved',?,?,?)""",
                (
                    attempt_id,
                    task_id,
                    candidates["id"],
                    candidates["owner_user_id"],
                    candidates["manager_broker_id"],
                    candidates["executor_type"],
                    candidates["executor_version"],
                    json_text(rate_snapshot),
                    fencing,
                    stamp,
                ),
            )
        task = row_dict(
            self.db.fetchone("SELECT * FROM tasks WHERE id=?", (task_id,)),
            json_columns={"public_requirements"},
        )
        task["worker"] = {
            "id": candidates["id"],
            "encryption_public_key": candidates["encryption_public_key"],
            "signing_public_key": candidates["signing_public_key"],
            "certificate": candidates["certificate"],
            "owner_root_signing_public_key": self.db.fetchone(
                "SELECT root_signing_public_key FROM users WHERE id=?",
                (candidates["owner_user_id"],),
            )["root_signing_public_key"],
            "executor_type": candidates["executor_type"],
            "executor_version": candidates["executor_version"],
        }
        task["allocation"] = self._allocation_security_view(candidates)
        task["rate_card_id"] = rate["id"]
        task["attempt_id"] = attempt_id
        task["content_attempt_id"] = attempt_id
        task["key_version"] = content_key_version
        task["fencing_token"] = fencing
        # Artifact stores replace these descriptors with signed PUT tickets.
        # The Gateway never embeds storage credentials in a Worker lease.
        task["artifact_tickets"] = []
        return task

    def commit_task(
        self,
        *,
        task_id: str,
        user_id: str | None,
        principal_type: str = "device",
        principal_id: str = "",
        encrypted_payload: str,
        worker_tdk_envelope: str,
        reader_envelope: str,
        key_algorithm: str,
        artifacts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task is None:
                raise RepositoryError(TASK_NOT_FOUND, "TASK_NOT_FOUND", "Task not found.", 404)
            self.require_task_consumer(
                task,
                principal_type=principal_type,
                principal_id=principal_id,
                user_id=user_id,
            )
            if task["state"] != "prepared":
                raise RepositoryError(
                    TASK_STATE_CONFLICT, "TASK_STATE_CONFLICT", "Task is not prepared.", 409
                )
            if task["reservation_expires_at"] <= stamp:
                conn.execute(
                    "UPDATE tasks SET state='expired',finished_at=?,updated_at=? WHERE id=?",
                    (stamp, stamp, task_id),
                )
                raise RepositoryError(
                    RESERVATION_EXPIRED,
                    "RESERVATION_EXPIRED",
                    "Task reservation has expired.",
                    409,
                    "later",
                )
            pending_inputs = conn.execute(
                """SELECT COUNT(*) AS n FROM artifacts
                   WHERE task_id=? AND direction='input' AND state!='uploaded'""",
                (task_id,),
            ).fetchone()["n"]
            if pending_inputs:
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "INPUT_ARTIFACT_NOT_UPLOADED",
                    "All encrypted input artifacts must be uploaded before commit.",
                    409,
                )
            conn.execute(
                """UPDATE tasks SET encrypted_payload=?,reader_envelope=?,state='committed',committed_at=?,updated_at=?
                   WHERE id=?""",
                (encrypted_payload, reader_envelope, stamp, stamp, task_id),
            )
            conn.execute(
                """INSERT INTO key_envelopes
                   (id,workspace_id,task_id,recipient_type,recipient_id,key_version,algorithm,envelope,created_at)
                   VALUES (?,?,?,'worker',?,?,?,?,?)""",
                (
                    new_id("ken"),
                    task["workspace_id"],
                    task_id,
                    task["assigned_worker_id"],
                    int(task["content_key_version"]),
                    key_algorithm,
                    worker_tdk_envelope,
                    stamp,
                ),
            )
        return row_dict(
            self.db.fetchone("SELECT * FROM tasks WHERE id=?", (task_id,)),
            json_columns={"public_requirements"},
        )

    def lease(self, *, worker_id: str, ttl_seconds: int) -> dict[str, Any] | None:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            self._expire_reservations(conn, stamp)
            self._expire_leases(conn, stamp)
            worker = conn.execute("SELECT * FROM workers WHERE id=?", (worker_id,)).fetchone()
            if worker is None:
                raise RepositoryError(
                    WORKER_NOT_FOUND, "WORKER_NOT_FOUND", "Worker not found.", 404
                )
            if worker["status"] == "draining":
                raise RepositoryError(
                    WORKER_DRAINING, "WORKER_DRAINING", "Worker is draining.", 409
                )
            if worker["status"] != "active":
                raise RepositoryError(
                    WORKER_OFFLINE, "WORKER_OFFLINE", "Worker is not active.", 409, "later"
                )
            maintenance = conn.execute(
                """SELECT state FROM worker_maintenance_jobs
                   WHERE worker_id=? AND state IN ('queued','leased','running','restarting')
                   ORDER BY created_at LIMIT 1""",
                (worker_id,),
            ).fetchone()
            task = conn.execute(
                """SELECT * FROM tasks
                   WHERE assigned_worker_id=? AND state='committed' AND reservation_expires_at>?
                   ORDER BY priority DESC,created_at LIMIT 1""",
                (worker_id, stamp),
            ).fetchone()
            if maintenance is not None:
                return None
            if task is None:
                return None
            attempt = conn.execute(
                """SELECT * FROM task_attempts
                   WHERE task_id=? AND worker_id=? AND state='reserved'
                   ORDER BY attempt_number DESC LIMIT 1""",
                (task["id"], worker_id),
            ).fetchone()
            if attempt is None:
                raise RepositoryError(
                    TASK_STATE_CONFLICT,
                    "ATTEMPT_STATE_CONFLICT",
                    "No reserved attempt exists for this task.",
                    409,
                )
            fencing = int(attempt["fencing_token"])
            attempt_id = attempt["id"]
            lease_id = new_id("lea")
            key = conn.execute(
                """SELECT envelope,key_version FROM key_envelopes
                   WHERE task_id=? AND recipient_type='worker' AND recipient_id=? AND revoked_at IS NULL
                   ORDER BY created_at DESC LIMIT 1""",
                (task["id"], worker_id),
            ).fetchone()
            if key is None:
                raise RepositoryError(
                    310002,
                    "REKEY_REQUIRED",
                    "The task key must be wrapped for this worker.",
                    409,
                    "rekey_required",
                )
            conn.execute(
                "UPDATE task_attempts SET state='leased',leased_at=? WHERE id=? AND state='reserved'",
                (stamp, attempt_id),
            )
            conn.execute(
                """INSERT INTO leases
                   (id,attempt_id,worker_id,fencing_token,encrypted_tdk_envelope,issued_at,expires_at,heartbeat_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    lease_id,
                    attempt_id,
                    worker_id,
                    fencing,
                    key["envelope"],
                    stamp,
                    stamp + ttl_seconds,
                    stamp,
                ),
            )
            conn.execute(
                "UPDATE tasks SET state='reserved',updated_at=? WHERE id=?", (stamp, task["id"])
            )
        artifacts = [
            row_dict(row, json_columns={"media_metadata"})
            for row in self.db.fetchall(
                "SELECT * FROM artifacts WHERE task_id=? AND direction='input'", (task["id"],)
            )
        ]
        requirements = json.loads(task["public_requirements"] or "{}")
        content_attempt = self.db.fetchone(
            "SELECT id FROM task_attempts WHERE task_id=? ORDER BY attempt_number LIMIT 1",
            (task["id"],),
        )
        return {
            "lease_id": lease_id,
            "attempt_id": attempt_id,
            "content_attempt_id": content_attempt["id"],
            "task_id": task["id"],
            "fencing_token": fencing,
            "expires_at": stamp + ttl_seconds,
            "workspace_id": task["workspace_id"],
            "executor_type": task["executor_type"],
            "payload_format": requirements.get("payload_format", "opaque/v1"),
            "operation": requirements.get("operation", "unknown"),
            "output_count": min(max(int(requirements.get("output_count", 1)), 1), 8),
            "key_version": int(key["key_version"]),
            "workflow_ref": task["workflow_ref"],
            "workflow_digest": task["workflow_digest"],
            "encrypted_payload": task["encrypted_payload"],
            "encrypted_tdk_envelope": key["envelope"],
            "artifacts": artifacts,
            "artifact_download_tickets": [
                {
                    "artifact_id": artifact["id"],
                    "store_type": artifact["store_type"],
                    "object_ref": artifact["object_ref"],
                }
                for artifact in artifacts
            ],
            "output_upload_tickets": [],
        }

    def heartbeat_attempt(
        self,
        *,
        attempt_id: str,
        worker_id: str,
        fencing_token: int,
        ttl_seconds: int,
        started: bool,
        progress: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            lease = conn.execute(
                """SELECT l.*,a.task_id,a.state AS attempt_state,t.state AS task_state
                   FROM leases l
                   JOIN task_attempts a ON a.id=l.attempt_id
                   JOIN tasks t ON t.id=a.task_id
                   WHERE l.attempt_id=? AND l.worker_id=? AND l.fencing_token=? AND l.released_at IS NULL""",
                (attempt_id, worker_id, fencing_token),
            ).fetchone()
            if lease is None or lease["expires_at"] <= stamp:
                cancelled = conn.execute(
                    """SELECT 1 FROM task_attempts a JOIN tasks t ON t.id=a.task_id
                       WHERE a.id=? AND a.worker_id=? AND a.fencing_token=? AND t.state='cancelled'""",
                    (attempt_id, worker_id, fencing_token),
                ).fetchone()
                if cancelled:
                    return {"ok": True, "cancelled": True, "expires_at": stamp}
                raise RepositoryError(
                    LEASE_LOST, "LEASE_LOST", "Lease is no longer valid.", 409, "none", "provider"
                )
            if lease["task_state"] == "cancelled":
                # A running cancellation is a two-phase terminal transition:
                # keep the exact fenced lease alive long enough for the Worker
                # to stop execution and submit its signed final usage report.
                conn.execute(
                    "UPDATE leases SET heartbeat_at=?,expires_at=? WHERE attempt_id=?",
                    (stamp, stamp + ttl_seconds, attempt_id),
                )
                return {"ok": True, "cancelled": True, "expires_at": stamp + ttl_seconds}
            conn.execute(
                "UPDATE leases SET heartbeat_at=?,expires_at=? WHERE attempt_id=?",
                (stamp, stamp + ttl_seconds, attempt_id),
            )
            if progress is not None:
                fraction = progress.get("fraction")
                stage = progress.get("stage", "")
                if (
                    not isinstance(fraction, (int, float))
                    or not 0 <= float(fraction) <= 1
                    or not isinstance(stage, str)
                ):
                    raise RepositoryError(
                        VALIDATION_FAILED, "PROGRESS_INVALID", "Progress is invalid.", 422
                    )
                conn.execute(
                    "UPDATE task_attempts SET progress=? WHERE id=?",
                    (json_text({"fraction": float(fraction), "stage": stage[:64]}), attempt_id),
                )
            if started and lease["attempt_state"] == "leased":
                conn.execute(
                    "UPDATE task_attempts SET state='running',started_at=? WHERE id=?",
                    (stamp, attempt_id),
                )
                conn.execute(
                    "UPDATE tasks SET state='running',updated_at=? WHERE id=?",
                    (stamp, lease["task_id"]),
                )
        return {"ok": True, "cancelled": False, "expires_at": stamp + ttl_seconds}

    def finish_attempt(
        self,
        *,
        attempt_id: str,
        worker_id: str,
        fencing_token: int,
        succeeded: bool,
        output_artifacts: list[dict[str, Any]],
        metrics: dict[str, Any],
        worker_signature: str | None,
        failure_code: int | None,
        responsibility: str,
        safe_failure_details: dict[str, Any] | None,
    ) -> dict[str, Any]:
        canonical_output_artifacts = [
            {
                **artifact,
                "media_metadata": self._artifact_media_metadata(artifact.get("media_metadata", {})),
            }
            for artifact in output_artifacts
        ]
        reported_metrics = self._validate_usage_metrics(metrics)
        canonical_failure_details = self._canonical_failure_details(safe_failure_details)
        canonical_failure_code, canonical_responsibility = self._canonical_attempt_outcome(
            succeeded=succeeded,
            failure_code=failure_code,
            reported_responsibility=responsibility,
        )
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            lease = conn.execute(
                """SELECT l.*,a.task_id,a.rate_snapshot,a.state AS attempt_state,
                          a.leased_at,a.started_at,t.workspace_id,t.state AS task_state
                   FROM leases l JOIN task_attempts a ON a.id=l.attempt_id JOIN tasks t ON t.id=a.task_id
                   WHERE l.attempt_id=? AND l.worker_id=? AND l.fencing_token=? AND l.released_at IS NULL""",
                (attempt_id, worker_id, fencing_token),
            ).fetchone()
            if (
                lease is None
                or lease["expires_at"] <= stamp
                or lease["attempt_state"] not in ("leased", "running")
            ):
                existing = conn.execute(
                    """SELECT a.state,t.id AS task_id,t.state AS task_state
                       FROM task_attempts a JOIN tasks t ON t.id=a.task_id
                       WHERE a.id=? AND a.worker_id=? AND a.fencing_token=?""",
                    (attempt_id, worker_id, fencing_token),
                ).fetchone()
                if (
                    existing is not None
                    and existing["state"] == "cancelled"
                    and existing["task_state"] == "cancelled"
                    and canonical_failure_code == int(ErrorCode.EXECUTION_CANCELLED)
                ):
                    # A pre-start cancellation has no ledger, while a repeated
                    # post-start terminal report already has one.  Both are
                    # safe idempotent acknowledgements for this exact fence.
                    return {
                        "attempt_id": attempt_id,
                        "task_id": existing["task_id"],
                        "state": "cancelled",
                    }
                raise RepositoryError(LEASE_LOST, "LEASE_LOST", "Lease is no longer valid.", 409)
            cancellation = lease["task_state"] == "cancelled"
            if canonical_failure_code == int(ErrorCode.EXECUTION_CANCELLED) and not cancellation:
                # A Worker cannot unilaterally attribute an executor abort to
                # the consumer. Consumer billing is allowed only after the
                # authorized task principal has requested cancellation.
                raise RepositoryError(
                    int(ErrorCode.USAGE_REPORT_INVALID),
                    "USAGE_REPORT_INVALID",
                    "A consumer cancellation report requires a cancelled task.",
                    422,
                    details={"reason": "cancellation_not_requested"},
                )
            if cancellation:
                attempt_state = "cancelled"
                task_state = "cancelled"
                canonical_failure_code = int(ErrorCode.EXECUTION_CANCELLED)
                canonical_responsibility = "consumer"
            else:
                attempt_state = "succeeded" if succeeded else "failed"
                task_state = "succeeded" if succeeded else "failed"
            conn.execute(
                """UPDATE task_attempts SET state=?,responsibility=?,failure_code=?,safe_failure_details=?,finished_at=?
                   WHERE id=?""",
                (
                    attempt_state,
                    canonical_responsibility,
                    canonical_failure_code,
                    json_text(canonical_failure_details),
                    stamp,
                    attempt_id,
                ),
            )
            conn.execute("UPDATE leases SET released_at=? WHERE attempt_id=?", (stamp, attempt_id))
            if not cancellation:
                conn.execute(
                    "UPDATE tasks SET state=?,finished_at=?,updated_at=? WHERE id=?",
                    (task_state, stamp, stamp, lease["task_id"]),
                )
            for artifact in [] if cancellation else canonical_output_artifacts:
                artifact_id = artifact.get("artifact_id")
                if not isinstance(artifact_id, str) or not artifact_id:
                    raise RepositoryError(
                        VALIDATION_FAILED,
                        "OUTPUT_ARTIFACT_INVALID",
                        "Output artifact requires its reserved artifact_id.",
                        422,
                    )
                updated = conn.execute(
                    """UPDATE artifacts SET kind=?,state='available',media_metadata=?,updated_at=?
                       WHERE id=? AND task_id=? AND attempt_id=? AND direction='output' AND state='uploaded'""",
                    (
                        artifact["kind"],
                        json_text(artifact.get("media_metadata", {})),
                        stamp,
                        artifact_id,
                        lease["task_id"],
                        attempt_id,
                    ),
                )
                if updated.rowcount != 1:
                    raise RepositoryError(
                        int(ErrorCode.ARTIFACT_NOT_FOUND),
                        "ARTIFACT_NOT_FOUND",
                        "Uploaded output artifact not found.",
                        404,
                    )
            # A reserved/leased attempt cancelled before the Worker marked it
            # running is deliberately a zero-use event with no charge entry.
            if not cancellation or lease["started_at"] is not None:
                event_id = new_id("use")
                conn.execute(
                    """INSERT INTO usage_events
                       (id,attempt_id,worker_id,event_kind,metrics,worker_signature,observed_at,created_at)
                       VALUES (?,?,?,'final',?,?,?,?)""",
                    (
                        event_id,
                        attempt_id,
                        worker_id,
                        json_text(reported_metrics),
                        worker_signature,
                        stamp,
                        stamp,
                    ),
                )
                canonical_metrics = self._canonical_usage_metrics(
                    reported_metrics,
                    observed_started_at=(
                        lease["started_at"] or lease["leased_at"] or lease["issued_at"]
                    ),
                    observed_finished_at=stamp,
                )
                if cancellation and "gpu_active_ms" not in canonical_metrics:
                    gpu_count = int(canonical_metrics.get("gpu_count", 1))
                    executor_wall_ms = int(canonical_metrics.get("executor_wall_ms", 0))
                    observed_capacity_ms = int(canonical_metrics["gateway_wall_ms"]) * gpu_count
                    canonical_metrics["gpu_active_ms"] = min(
                        executor_wall_ms * gpu_count,
                        observed_capacity_ms,
                    )
                    canonical_metrics["anomaly_flags"].append(
                        "cancelled_gpu_active_derived_from_executor_wall"
                    )
                self._append_ledger(
                    conn,
                    attempt_id,
                    lease["rate_snapshot"],
                    canonical_metrics,
                    succeeded and not cancellation,
                    canonical_responsibility,
                    stamp,
                )
            worker_state = conn.execute(
                "SELECT status FROM workers WHERE id=?", (worker_id,)
            ).fetchone()
            if worker_state and worker_state["status"] == "draining":
                self._finalize_drained_workers(conn, stamp)
        return {"attempt_id": attempt_id, "task_id": lease["task_id"], "state": attempt_state}

    @staticmethod
    def _canonical_failure_details(details: dict[str, Any] | None) -> dict[str, Any]:
        """Keep only bounded diagnostic codes, never Worker-supplied prose.

        A Worker necessarily sees task plaintext and is not trusted to decide
        what may be persisted by the Gateway.  Free-form strings could smuggle
        a prompt or signed capability into an otherwise "safe" error field.
        """

        if not isinstance(details, dict):
            return {}
        canonical: dict[str, Any] = {}
        for key in sorted(_SAFE_FAILURE_DETAIL_KEYS & details.keys()):
            value = details[key]
            if (
                isinstance(value, str)
                and 0 < len(value) <= 96
                and set(value) <= _SAFE_FAILURE_DETAIL_CHARACTERS
                and "://" not in value
            ):
                canonical[key] = value
        for key in sorted(_SAFE_FAILURE_DETAIL_NUMERIC_KEYS & details.keys()):
            value = details[key]
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000:
                canonical[key] = value
        return canonical

    @staticmethod
    def _canonical_attempt_outcome(
        *,
        succeeded: bool,
        failure_code: int | None,
        reported_responsibility: str,
    ) -> tuple[int | None, str]:
        if succeeded:
            if failure_code is not None or reported_responsibility != "none":
                raise RepositoryError(
                    int(ErrorCode.USAGE_REPORT_INVALID),
                    "USAGE_REPORT_INVALID",
                    "A successful attempt must not report failure attribution.",
                    422,
                    details={"reason": "successful_attempt_attribution_invalid"},
                )
            return None, "none"
        if failure_code is None:
            raise RepositoryError(
                int(ErrorCode.USAGE_REPORT_INVALID),
                "USAGE_REPORT_INVALID",
                "A failed attempt must report a registered failure code.",
                422,
                details={"reason": "failure_code_required"},
            )
        try:
            registered_code = ErrorCode(failure_code)
            registered_responsibility = get_error_spec(registered_code).responsibility.value
        except (KeyError, ValueError) as exc:
            raise RepositoryError(
                int(ErrorCode.USAGE_REPORT_INVALID),
                "USAGE_REPORT_INVALID",
                "A failed attempt must report a registered failure code.",
                422,
                details={"reason": "failure_code_unregistered"},
            ) from exc
        canonical_responsibility = (
            "consumer"
            if registered_code == ErrorCode.EXECUTION_CANCELLED
            else (
                "platform" if registered_responsibility == "unknown" else registered_responsibility
            )
        )
        if reported_responsibility != canonical_responsibility:
            raise RepositoryError(
                int(ErrorCode.USAGE_REPORT_INVALID),
                "USAGE_REPORT_INVALID",
                "The reported failure responsibility does not match the error registry.",
                422,
                details={
                    "reason": "responsibility_mismatch",
                    "canonical_responsibility": canonical_responsibility,
                    "reported_responsibility": reported_responsibility,
                },
            )
        return int(registered_code), canonical_responsibility

    @staticmethod
    def _canonical_usage_metrics(
        reported_metrics: dict[str, Any],
        *,
        observed_started_at: float,
        observed_finished_at: float,
    ) -> dict[str, Any]:
        canonical = dict(reported_metrics)
        observed_wall_ms = min(
            _USAGE_MAX_WALL_MS,
            max(0, math.ceil((observed_finished_at - observed_started_at) * 1000)),
        )
        anomaly_flags: list[str] = []
        reported_wall_ms = reported_metrics.get("gateway_wall_ms")
        wall_tolerance_ms = max(1_000, observed_wall_ms // 10)
        if (
            reported_wall_ms is not None
            and abs(int(reported_wall_ms) - observed_wall_ms) > wall_tolerance_ms
        ):
            anomaly_flags.append("gateway_wall_report_mismatch")
        gpu_active_ms = int(reported_metrics.get("gpu_active_ms", 0))
        gpu_count = int(reported_metrics.get("gpu_count", 1))
        observed_capacity_ms = observed_wall_ms * gpu_count
        capacity_tolerance_ms = max(1_000 * gpu_count, observed_capacity_ms // 10)
        if gpu_active_ms > observed_capacity_ms + capacity_tolerance_ms:
            anomaly_flags.append("gpu_active_exceeds_observed_capacity")
        canonical["gateway_wall_ms"] = observed_wall_ms
        canonical["anomaly_flags"] = anomaly_flags
        return canonical

    @staticmethod
    def _validate_usage_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(metrics, dict):
            raise RepositoryError(
                500001, "USAGE_REPORT_INVALID", "Usage metrics must be an object.", 422
            )
        allowed = {
            "gpu_active_ms",
            "executor_wall_ms",
            "gateway_wall_ms",
            "gpu_count",
            "input_bytes",
            "output_bytes",
            "upload_bytes",
            "download_bytes",
            "egress_bytes",
            "frames",
            "output_frames",
            "duration_ms",
            "denoise_steps",
            "native",
        }
        if set(metrics) - allowed:
            raise RepositoryError(
                500001,
                "USAGE_REPORT_INVALID",
                "Usage metrics include unsupported fields.",
                422,
                details={"reason": "unsupported_usage_fields"},
            )
        maxima = {
            "gpu_active_ms": 30 * 24 * 60 * 60 * 1000,
            "executor_wall_ms": 30 * 24 * 60 * 60 * 1000,
            "gateway_wall_ms": _USAGE_MAX_WALL_MS,
            "gpu_count": 64,
            "input_bytes": 1024**5,
            "output_bytes": 1024**5,
            "upload_bytes": 1024**5,
            "download_bytes": 1024**5,
            "egress_bytes": 1024**5,
            "frames": 100_000_000,
            "output_frames": 100_000_000,
            "duration_ms": 30 * 24 * 60 * 60 * 1000,
            "denoise_steps": 10_000_000,
        }
        normalized: dict[str, Any] = {}
        for key, value in metrics.items():
            if key == "native":
                if not isinstance(value, dict) or len(value) > _NATIVE_USAGE_MAX_ENTRIES:
                    raise RepositoryError(
                        500001, "USAGE_REPORT_INVALID", "Native usage metrics are invalid.", 422
                    )
                native: dict[str, int | float | bool | None] = {}
                for native_key, native_value in value.items():
                    valid_key = (
                        isinstance(native_key, str)
                        and 0 < len(native_key) <= _NATIVE_USAGE_MAX_KEY_LENGTH
                        and set(native_key) <= _NATIVE_USAGE_KEY_CHARACTERS
                    )
                    valid_value = False
                    if native_value is None or isinstance(native_value, bool):
                        valid_value = True
                    elif isinstance(native_value, int):
                        valid_value = abs(native_value) <= _NATIVE_USAGE_MAX_ABSOLUTE_NUMBER
                    elif isinstance(native_value, float):
                        valid_value = (
                            math.isfinite(native_value)
                            and abs(native_value) <= _NATIVE_USAGE_MAX_ABSOLUTE_NUMBER
                        )
                    if not valid_key or not valid_value:
                        raise RepositoryError(
                            500001,
                            "USAGE_REPORT_INVALID",
                            "Native usage metrics must be a flat map of bounded numeric values.",
                            422,
                        )
                    native[native_key] = native_value
                if len(json_text(native).encode("utf-8")) > _NATIVE_USAGE_MAX_SERIALIZED_BYTES:
                    raise RepositoryError(
                        500001,
                        "USAGE_REPORT_INVALID",
                        "Native usage metrics exceed the serialized size limit.",
                        422,
                    )
                normalized[key] = native
                continue
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > maxima[key]
            ):
                raise RepositoryError(
                    500001,
                    "USAGE_REPORT_INVALID",
                    "Usage metric is outside its accepted range.",
                    422,
                    details={"field": key},
                )
            normalized[key] = value
        gpu_count = normalized.get("gpu_count")
        if gpu_count is not None and gpu_count < 1:
            raise RepositoryError(
                500001, "USAGE_REPORT_INVALID", "gpu_count must be positive.", 422
            )
        return normalized

    def _append_ledger(
        self,
        conn: sqlite3.Connection,
        attempt_id: str,
        rate_snapshot_text: str,
        metrics: dict[str, Any],
        succeeded: bool,
        responsibility: str,
        stamp: float,
    ) -> None:
        rate = json.loads(rate_snapshot_text)
        gpu_active_ms = max(0, int(metrics.get("gpu_active_ms", 0)))
        multiplier = max(0, int(rate.get("workflow_multiplier_ppm", 1_000_000)))
        per_second = max(0, int(rate.get("rate_microtokens_per_gpu_second", 0)))
        # gpu_active_ms is aggregate active accelerator time across the reported
        # gpu_count; the rate therefore applies once and gpu_count is not multiplied again.
        numerator = gpu_active_ms * per_second * multiplier
        denominator = 1_000 * 1_000_000
        compute = (numerator + denominator - 1) // denominator
        egress = max(0, int(metrics.get("egress_bytes", 0)))
        traffic_rate = max(0, int(rate.get("traffic_microtokens_per_gib", 0)))
        traffic_numerator = egress * traffic_rate
        traffic_denominator = 1024**3
        traffic = (traffic_numerator + traffic_denominator - 1) // traffic_denominator
        billable = succeeded or responsibility == "consumer"
        if responsibility in ("provider", "platform"):
            billable = False
        if not billable:
            compute = 0
            traffic = 0
        prior = conn.execute(
            "SELECT integrity_hash FROM usage_ledger ORDER BY created_at DESC,id DESC LIMIT 1"
        ).fetchone()
        previous_hash = prior["integrity_hash"] if prior else None
        payload = {
            "attempt_id": attempt_id,
            "entry_type": "charge",
            "metrics": metrics,
            "rate_snapshot": rate,
            "compute_microtokens": compute,
            "traffic_microtokens": traffic,
            "billable": billable,
            "responsibility": responsibility,
            "previous_hash": previous_hash,
            "created_at": stamp,
        }
        integrity_hash = hashlib.sha256(json_text(payload).encode()).hexdigest()
        conn.execute(
            """INSERT INTO usage_ledger
               (id,attempt_id,entry_type,metrics,rate_snapshot,compute_microtokens,traffic_microtokens,
                total_microtokens,billable,responsibility,formula_version,previous_hash,integrity_hash,created_at)
               VALUES (?,?,'charge',?,?,?,?,?,?,?,?,?,?,?)""",
            (
                new_id("led"),
                attempt_id,
                json_text(metrics),
                rate_snapshot_text,
                compute,
                traffic,
                compute + traffic,
                int(billable),
                responsibility,
                int(rate.get("formula_version", 1)),
                previous_hash,
                integrity_hash,
                stamp,
            ),
        )

    def get_task(
        self,
        *,
        task_id: str,
        user_id: str | None,
        principal_type: str = "device",
        principal_id: str = "",
    ) -> dict[str, Any]:
        task = self.db.fetchone("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise RepositoryError(TASK_NOT_FOUND, "TASK_NOT_FOUND", "Task not found.", 404)
        if principal_type == "service":
            self.require_task_consumer(
                task,
                principal_type=principal_type,
                principal_id=principal_id,
                user_id=user_id,
            )
        else:
            self.require_member(task["workspace_id"], user_id)
        value = row_dict(task, json_columns={"public_requirements"})
        # Deliberately omit encrypted payloads and key envelopes from ordinary metadata reads.
        value.pop("encrypted_payload", None)
        value.pop("reader_envelope", None)
        value["attempts"] = [
            row_dict(row, json_columns={"rate_snapshot", "safe_failure_details"})
            for row in self.db.fetchall(
                "SELECT * FROM task_attempts WHERE task_id=? ORDER BY attempt_number", (task_id,)
            )
        ]
        value["artifacts"] = [
            row_dict(row, json_columns={"media_metadata"})
            for row in self.db.fetchall(
                "SELECT * FROM artifacts WHERE task_id=? ORDER BY created_at", (task_id,)
            )
        ]
        return value

    def list_tasks(
        self,
        *,
        workspace_id: str,
        user_id: str | None,
        principal_type: str = "device",
        principal_id: str = "",
        state: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if principal_type == "service":
            self.require_service(workspace_id, principal_id)
        else:
            self.require_member(workspace_id, user_id)
        sql = "SELECT * FROM tasks WHERE workspace_id=?"
        args: list[Any] = [workspace_id]
        if principal_type == "service":
            sql += " AND consumer_principal_type='service' AND consumer_principal_id=?"
            args.append(principal_id)
        if state:
            sql += " AND state=?"
            args.append(state)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(min(max(limit, 1), 500))
        values: list[dict[str, Any]] = []
        for row in self.db.fetchall(sql, tuple(args)):
            value = row_dict(row, json_columns={"public_requirements"})
            value.pop("encrypted_payload", None)
            value.pop("reader_envelope", None)
            values.append(value)
        return values

    def cancel_task(
        self,
        *,
        task_id: str,
        user_id: str | None,
        principal_type: str = "device",
        principal_id: str = "",
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task is None:
                raise RepositoryError(300002, "TASK_NOT_FOUND", "Task not found.", 404)
            self.require_task_consumer(
                task,
                principal_type=principal_type,
                principal_id=principal_id,
                user_id=user_id,
                allow_workspace_admin=True,
            )
            if task["state"] in ("succeeded", "failed", "cancelled", "expired"):
                return {"task_id": task_id, "state": task["state"]}
            conn.execute(
                "UPDATE tasks SET state='cancelled',finished_at=?,updated_at=? WHERE id=?",
                (stamp, stamp, task_id),
            )
            # Running attempts retain their fenced lease until the Worker
            # acknowledges cancellation with a signed usage report.  Attempts
            # that never started are terminal immediately and generate no
            # usage event or ledger entry.
            conn.execute(
                """UPDATE task_attempts SET state='cancelled',responsibility='consumer',finished_at=?
                   WHERE task_id=? AND state IN ('reserved','leased')""",
                (stamp, task_id),
            )
            conn.execute(
                """UPDATE leases SET released_at=? WHERE attempt_id IN
                   (SELECT id FROM task_attempts
                    WHERE task_id=? AND state='cancelled' AND started_at IS NULL)
                   AND released_at IS NULL""",
                (stamp, task_id),
            )
        return {"task_id": task_id, "state": "cancelled"}

    def prepare_retry(
        self,
        *,
        task_id: str,
        user_id: str | None,
        principal_type: str = "device",
        principal_id: str = "",
        reservation_ttl_seconds: int = 120,
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            self._expire_reservations(conn, stamp)
            task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task is None:
                raise RepositoryError(300002, "TASK_NOT_FOUND", "Task not found.", 404)
            self.require_task_consumer(
                task,
                principal_type=principal_type,
                principal_id=principal_id,
                user_id=user_id,
                allow_workspace_admin=True,
            )
            if task["state"] not in ("failed", "rekey_required", "expired"):
                raise RepositoryError(
                    TASK_STATE_CONFLICT,
                    "TASK_STATE_CONFLICT",
                    "Task cannot be retried from its current state.",
                    409,
                )
            if not task["encrypted_payload"] or not task["reader_envelope"]:
                raise RepositoryError(
                    TASK_STATE_CONFLICT,
                    "TASK_RETRY_CONTENT_UNAVAILABLE",
                    "An uncommitted or content-less task must be submitted again.",
                    409,
                )
            requirements = self._public_requirements(
                json.loads(task["public_requirements"] or "{}")
            )
            candidate_rows = conn.execute(
                """SELECT w.*,a.id AS allocation_id,a.allocation_proof AS allocation_proof,
                          a.approved_by_user_id AS allocation_approved_by,
                          a.owner_consent_at AS allocation_owner_consent_at
                   FROM workers w JOIN worker_allocations a ON a.worker_id=w.id
                   WHERE a.pool_id=? AND a.status='active' AND a.allocation_proof IS NOT NULL
                     AND w.status='active'
                     AND NOT EXISTS (
                       SELECT 1 FROM worker_maintenance_jobs mj
                       WHERE mj.worker_id=w.id
                         AND mj.state IN ('queued','leased','running','restarting')
                     )
                     AND w.id!=? AND w.executor_type=? AND w.last_seen_at>?
                     AND (SELECT COUNT(*) FROM task_attempts ta JOIN tasks active_task ON active_task.id=ta.task_id
                          WHERE ta.worker_id=w.id AND ta.state IN ('reserved','leased','running')
                            AND (active_task.reservation_expires_at IS NULL OR active_task.reservation_expires_at>?)) < w.capacity
                   ORDER BY w.last_seen_at DESC,w.created_at LIMIT 50""",
                (
                    task["pool_id"],
                    task["assigned_worker_id"],
                    task["executor_type"],
                    stamp - WORKER_ONLINE_WINDOW_SECONDS,
                    stamp,
                ),
            ).fetchall()
            candidate = next(
                (row for row in candidate_rows if self._matches_requirements(row, requirements)),
                None,
            )
            if candidate is None:
                raise RepositoryError(
                    NO_ELIGIBLE_WORKER,
                    "NO_ELIGIBLE_WORKER",
                    "No eligible worker is currently available.",
                    503,
                )
            rate = conn.execute(
                """SELECT * FROM rate_cards WHERE worker_id=? AND workspace_id=? AND status='approved'
                   ORDER BY decided_at DESC LIMIT 1""",
                (candidate["id"], task["workspace_id"]),
            ).fetchone()
            if rate is None:
                raise RepositoryError(
                    RATE_NOT_APPROVED,
                    "RATE_NOT_APPROVED",
                    "The replacement worker has no approved rate.",
                    409,
                )
            fencing = int(candidate["fencing_counter"]) + 1
            attempt_number = int(
                conn.execute(
                    "SELECT COALESCE(MAX(attempt_number),0)+1 AS n FROM task_attempts WHERE task_id=?",
                    (task_id,),
                ).fetchone()["n"]
            )
            attempt_id = new_id("atm")
            rate_snapshot = {
                "rate_card_id": rate["id"],
                "rate_microtokens_per_gpu_second": rate["rate_microtokens_per_gpu_second"],
                "traffic_microtokens_per_gib": rate["traffic_microtokens_per_gib"],
                "workflow_multiplier_ppm": 1_000_000,
                "formula_version": rate["formula_version"],
            }
            conn.execute(
                "UPDATE workers SET fencing_counter=?,updated_at=? WHERE id=?",
                (fencing, stamp, candidate["id"]),
            )
            conn.execute(
                """INSERT INTO task_attempts
                   (id,task_id,attempt_number,worker_id,provider_user_id,manager_broker_id,executor_type,
                    executor_version,state,rate_snapshot,fencing_token,reserved_at)
                   VALUES (?,?,?,?,?,?,?,?,'reserved',?,?,?)""",
                (
                    attempt_id,
                    task_id,
                    attempt_number,
                    candidate["id"],
                    candidate["owner_user_id"],
                    candidate["manager_broker_id"],
                    candidate["executor_type"],
                    candidate["executor_version"],
                    json_text(rate_snapshot),
                    fencing,
                    stamp,
                ),
            )
            conn.execute(
                """UPDATE tasks SET assigned_worker_id=?,reservation_expires_at=?,state='rekey_required',
                   finished_at=NULL,updated_at=? WHERE id=?""",
                (candidate["id"], stamp + reservation_ttl_seconds, stamp, task_id),
            )
        return {
            "task_id": task_id,
            "workspace_id": task["workspace_id"],
            "pool_id": task["pool_id"],
            "state": "rekey_required",
            "key_version": int(task["content_key_version"]),
            "attempt_id": attempt_id,
            "content_attempt_id": self.db.fetchone(
                "SELECT id FROM task_attempts WHERE task_id=? ORDER BY attempt_number LIMIT 1",
                (task_id,),
            )["id"],
            "fencing_token": fencing,
            "reservation_expires_at": stamp + reservation_ttl_seconds,
            "worker": {
                "id": candidate["id"],
                "signing_public_key": candidate["signing_public_key"],
                "encryption_public_key": candidate["encryption_public_key"],
                "certificate": candidate["certificate"],
                "owner_root_signing_public_key": self.db.fetchone(
                    "SELECT root_signing_public_key FROM users WHERE id=?",
                    (candidate["owner_user_id"],),
                )["root_signing_public_key"],
                "executor_type": candidate["executor_type"],
                "executor_version": candidate["executor_version"],
            },
            "allocation": self._allocation_security_view(candidate),
        }

    def commit_rekey(
        self,
        *,
        task_id: str,
        user_id: str | None,
        replacement_worker_id: str,
        worker_tdk_envelope: str,
        key_algorithm: str,
        principal_type: str = "device",
        principal_id: str = "",
    ) -> dict[str, Any]:
        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task is None:
                raise RepositoryError(300002, "TASK_NOT_FOUND", "Task not found.", 404)
            self.require_task_consumer(
                task,
                principal_type=principal_type,
                principal_id=principal_id,
                user_id=user_id,
            )
            if (
                task["state"] != "rekey_required"
                or task["assigned_worker_id"] != replacement_worker_id
            ):
                raise RepositoryError(
                    TASK_STATE_CONFLICT,
                    "TASK_STATE_CONFLICT",
                    "Task has no matching rekey reservation.",
                    409,
                )
            if task["reservation_expires_at"] <= stamp:
                raise RepositoryError(
                    RESERVATION_EXPIRED,
                    "RESERVATION_EXPIRED",
                    "Rekey reservation has expired.",
                    409,
                )
            conn.execute(
                "UPDATE key_envelopes SET revoked_at=? WHERE task_id=? AND recipient_type='worker' AND revoked_at IS NULL",
                (stamp, task_id),
            )
            conn.execute(
                """INSERT INTO key_envelopes
                   (id,workspace_id,task_id,recipient_type,recipient_id,key_version,algorithm,envelope,created_at)
                   VALUES (?,?,?,'worker',?,?,?,?,?)""",
                (
                    new_id("ken"),
                    task["workspace_id"],
                    task_id,
                    replacement_worker_id,
                    int(task["content_key_version"]),
                    key_algorithm,
                    worker_tdk_envelope,
                    stamp,
                ),
            )
            conn.execute(
                "UPDATE tasks SET state='committed',updated_at=? WHERE id=?", (stamp, task_id)
            )
        return {"task_id": task_id, "state": "committed", "worker_id": replacement_worker_id}

    def reader_envelope(
        self,
        *,
        task_id: str,
        user_id: str | None,
        principal_type: str = "device",
        principal_id: str = "",
    ) -> dict[str, Any]:
        task = self.db.fetchone("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise RepositoryError(300002, "TASK_NOT_FOUND", "Task not found.", 404)
        self.require_task_consumer(
            task,
            principal_type=principal_type,
            principal_id=principal_id,
            user_id=user_id,
            allow_workspace_admin=True,
        )
        content_attempt = self.db.fetchone(
            "SELECT id FROM task_attempts WHERE task_id=? ORDER BY attempt_number LIMIT 1",
            (task_id,),
        )
        return {
            "task_id": task_id,
            "workspace_id": task["workspace_id"],
            "reader_envelope": task["reader_envelope"],
            "key_version": int(task["content_key_version"]),
            "content_attempt_id": content_attempt["id"] if content_attempt else None,
            "assigned_worker_id": task["assigned_worker_id"],
        }

    def list_enrollments(
        self, *, workspace_id: str, user_id: str, state: str | None
    ) -> list[dict[str, Any]]:
        self.require_admin(workspace_id, user_id)
        sql = "SELECT * FROM enrollments WHERE workspace_id=?"
        args: list[Any] = [workspace_id]
        if state:
            sql += " AND state=?"
            args.append(state)
        sql += " ORDER BY created_at DESC LIMIT 500"
        return [self.enrollment(str(row["id"])) for row in self.db.fetchall(sql, tuple(args))]

    def list_audit(self, *, workspace_id: str, user_id: str, limit: int) -> list[dict[str, Any]]:
        self.require_admin(workspace_id, user_id)
        return [
            row_dict(row, json_columns={"safe_details"})
            for row in self.db.fetchall(
                """SELECT * FROM audit_events WHERE workspace_id=?
                   ORDER BY created_at DESC LIMIT ?""",
                (workspace_id, min(max(limit, 1), 500)),
            )
        ]

    def usage(
        self,
        *,
        workspace_id: str,
        user_id: str | None,
        limit: int,
        principal_type: str = "device",
        principal_id: str = "",
    ) -> list[dict[str, Any]]:
        if principal_type == "service":
            self.require_service(workspace_id, principal_id)
            access_mode = "service"
        else:
            self.require_user(user_id)
            membership = self.membership(workspace_id, user_id)
            if membership is not None and membership["role"] in ("owner", "admin"):
                access_mode = "all"
            elif membership is not None:
                access_mode = "member"
            else:
                approved_provider = self.db.fetchone(
                    """SELECT 1 AS allowed FROM worker_allocations wa
                       JOIN workers w ON w.id=wa.worker_id
                       WHERE wa.workspace_id=? AND w.owner_user_id=?
                         AND wa.workspace_approved_at IS NOT NULL
                       UNION ALL
                       SELECT 1 AS allowed FROM task_attempts a
                       JOIN tasks t ON t.id=a.task_id
                       JOIN workers w ON w.id=a.worker_id
                       WHERE t.workspace_id=? AND a.provider_user_id=?
                         AND w.owner_user_id=?
                       LIMIT 1""",
                    (workspace_id, user_id, workspace_id, user_id, user_id),
                )
                if approved_provider is None:
                    raise RepositoryError(
                        FORBIDDEN,
                        "WORKSPACE_ACCESS_DENIED",
                        "Workspace usage access denied.",
                        403,
                    )
                access_mode = "provider"
        access_user_id = user_id or ""
        rows = self.db.fetchall(
            """SELECT l.*,a.worker_id,a.task_id,t.consumer_user_id,
                      t.consumer_principal_type,t.consumer_principal_id,t.client_channel,
                      t.workflow_ref,t.workflow_digest
               FROM usage_ledger l JOIN task_attempts a ON a.id=l.attempt_id JOIN tasks t ON t.id=a.task_id
               WHERE t.workspace_id=?
                 AND (
                   ?='all'
                   OR (?='member' AND (t.consumer_user_id=? OR a.provider_user_id=?))
                   OR (?='provider' AND a.provider_user_id=?)
                   OR (?='service' AND t.consumer_principal_type='service'
                                      AND t.consumer_principal_id=?)
                 )
               ORDER BY l.created_at DESC LIMIT ?""",
            (
                workspace_id,
                access_mode,
                access_mode,
                access_user_id,
                access_user_id,
                access_mode,
                access_user_id,
                access_mode,
                principal_id,
                min(max(limit, 1), 500),
            ),
        )
        return [row_dict(row, json_columns={"metrics", "rate_snapshot"}) for row in rows]

    def reverse_usage_charge(
        self,
        *,
        workspace_id: str,
        ledger_id: str,
        user_id: str | None,
        reason_code: str,
    ) -> dict[str, Any]:
        """Append exactly one negative correction for a billable charge.

        This operation never updates the original ledger entry.  The unique
        ``reverses_ledger_id`` index and the immediate transaction make retries
        semantically idempotent even when no HTTP Idempotency-Key is supplied.
        """

        self.require_admin(workspace_id, user_id)
        if reason_code not in USAGE_REVERSAL_REASON_CODES:
            raise RepositoryError(
                VALIDATION_FAILED,
                "USAGE_REVERSAL_REASON_INVALID",
                "Usage reversal reason code is invalid.",
                422,
                details={"field": "reason_code"},
            )

        stamp = now()
        with self.db.transaction(immediate=True) as conn:
            original = conn.execute(
                """SELECT l.* FROM usage_ledger l
                   JOIN task_attempts a ON a.id=l.attempt_id
                   JOIN tasks t ON t.id=a.task_id
                   WHERE l.id=? AND t.workspace_id=?""",
                (ledger_id, workspace_id),
            ).fetchone()
            if original is None:
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "USAGE_ENTRY_NOT_FOUND",
                    "Usage ledger entry not found.",
                    404,
                )

            existing = conn.execute(
                "SELECT * FROM usage_ledger WHERE reverses_ledger_id=?",
                (ledger_id,),
            ).fetchone()
            if existing is not None:
                return row_dict(existing, json_columns={"metrics", "rate_snapshot"})

            compute = int(original["compute_microtokens"])
            traffic = int(original["traffic_microtokens"])
            total = int(original["total_microtokens"])
            if (
                original["entry_type"] != "charge"
                or not bool(original["billable"])
                or compute < 0
                or traffic < 0
                or total < 0
                or total != compute + traffic
            ):
                raise RepositoryError(
                    VALIDATION_FAILED,
                    "USAGE_ENTRY_NOT_REVERSIBLE",
                    "Usage ledger entry is not a reversible billable charge.",
                    409,
                )

            prior = conn.execute(
                "SELECT integrity_hash FROM usage_ledger ORDER BY created_at DESC,id DESC LIMIT 1"
            ).fetchone()
            previous_hash = prior["integrity_hash"] if prior else None
            metrics = json.loads(original["metrics"])
            rate_snapshot = json.loads(original["rate_snapshot"])
            payload = {
                "attempt_id": original["attempt_id"],
                "entry_type": "reversal",
                "metrics": metrics,
                "rate_snapshot": rate_snapshot,
                "compute_microtokens": -compute,
                "traffic_microtokens": -traffic,
                "total_microtokens": -total,
                "billable": True,
                "responsibility": original["responsibility"],
                "formula_version": int(original["formula_version"]),
                "previous_hash": previous_hash,
                "reverses_ledger_id": ledger_id,
                "reversal_reason_code": reason_code,
                "created_at": stamp,
            }
            integrity_hash = hashlib.sha256(json_text(payload).encode()).hexdigest()
            reversal_id = new_id("led")
            conn.execute(
                """INSERT INTO usage_ledger
                   (id,attempt_id,entry_type,metrics,rate_snapshot,compute_microtokens,
                    traffic_microtokens,total_microtokens,billable,responsibility,
                    formula_version,previous_hash,integrity_hash,reverses_ledger_id,
                    reversal_reason_code,created_at)
                   VALUES (?,?,'reversal',?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    reversal_id,
                    original["attempt_id"],
                    original["metrics"],
                    original["rate_snapshot"],
                    -compute,
                    -traffic,
                    -total,
                    1,
                    original["responsibility"],
                    int(original["formula_version"]),
                    previous_hash,
                    integrity_hash,
                    ledger_id,
                    reason_code,
                    stamp,
                ),
            )
            conn.execute(
                """INSERT INTO audit_events
                   (id,actor_type,actor_id,workspace_id,action,subject_type,subject_id,
                    safe_details,created_at)
                   VALUES (?, 'user',?,?,'usage.charge_reversed','usage_ledger',?,?,?)""",
                (
                    new_id("aud"),
                    user_id,
                    workspace_id,
                    ledger_id,
                    json_text(
                        {
                            "reason_code": reason_code,
                            "reversal_ledger_id": reversal_id,
                        }
                    ),
                    stamp,
                ),
            )
            reversal = conn.execute(
                "SELECT * FROM usage_ledger WHERE id=?", (reversal_id,)
            ).fetchone()
        return row_dict(reversal, json_columns={"metrics", "rate_snapshot"})
