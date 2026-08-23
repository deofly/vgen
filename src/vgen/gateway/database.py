"""SQLite persistence for the single-node Gateway v1 control plane.

The schema deliberately stores only scheduling metadata and opaque encrypted
payloads.  Plain prompts, workflow parameters and artifact contents never
belong in this database.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from vgen.protocol.ids import new_id as protocol_new_id

SCHEMA_VERSION = 1
WORKER_ONLINE_WINDOW_SECONDS = 120.0
TRANSFER_TICKET_REPLAY_RETENTION_SECONDS = 7_200.0


def new_id(prefix: str) -> str:
    """Compatibility helper for terse repository call sites using ID prefixes."""
    kind_by_prefix = {
        "usr": "user",
        "dev": "device",
        "brk": "broker",
        "bdev": "broker_device",
        "bcm": "broker_command",
        "wsp": "workspace",
        "pol": "pool",
        "wrk": "worker",
        "mtj": "worker_maintenance_job",
        "alc": "allocation",
        "inv": "invite",
        "app": "application",
        "enr": "enrollment",
        "ses": "session",
        "chl": "session",
        "tsk": "task",
        "atm": "attempt",
        "lea": "lease",
        "art": "artifact",
        "use": "usage_event",
        "led": "usage_ledger",
        "rat": "rate_card",
        "kmf": "key_manifest",
        "ken": "key_envelope",
        "aud": "audit_event",
        "svc": "service",
    }
    try:
        return protocol_new_id(kind_by_prefix[prefix])
    except KeyError as exc:
        raise ValueError(f"unknown ID prefix: {prefix}") from exc


def now() -> float:
    return time.time()


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


SCHEMA = r"""
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    root_signing_public_key TEXT NOT NULL UNIQUE,
    root_encryption_public_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','suspended','revoked')),
    is_operator INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    signing_public_key TEXT NOT NULL UNIQUE,
    encryption_public_key TEXT NOT NULL,
    certificate TEXT,
    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
    created_at REAL NOT NULL,
    last_seen_at REAL,
    revoked_at REAL
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id, status);

CREATE TABLE IF NOT EXISTS device_recovery_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    device_id TEXT NOT NULL,
    challenge_value TEXT NOT NULL,
    challenge_hash TEXT NOT NULL,
    expires_at REAL NOT NULL,
    consumed_at REAL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_recovery_challenges_subject
    ON device_recovery_challenges(user_id, device_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_device_recovery_challenges_expiry
    ON device_recovery_challenges(expires_at);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL CHECK(principal_type IN ('device','worker')),
    principal_id TEXT NOT NULL,
    challenge_value TEXT NOT NULL,
    challenge_hash TEXT NOT NULL,
    expires_at REAL NOT NULL,
    consumed_at REAL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expiry ON auth_challenges(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL CHECK(principal_type IN ('device','service','worker')),
    principal_id TEXT NOT NULL,
    user_id TEXT REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    expires_at REAL NOT NULL,
    revoked_at REAL,
    created_at REAL NOT NULL,
    last_seen_at REAL
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    signing_public_key TEXT NOT NULL UNIQUE,
    encryption_public_key TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL CHECK(status IN ('pending','active','revoked')),
    created_by_user_id TEXT REFERENCES users(id),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    revoked_at REAL
);
CREATE INDEX IF NOT EXISTS idx_services_workspace ON services(workspace_id, status);

-- Kept separate from auth_challenges so existing v1 SQLite databases whose
-- CHECK constraint predates Service principals can be upgraded in place.
CREATE TABLE IF NOT EXISTS service_auth_challenges (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id),
    challenge_value TEXT NOT NULL,
    challenge_hash TEXT NOT NULL,
    expires_at REAL NOT NULL,
    consumed_at REAL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_service_auth_challenges_expiry
    ON service_auth_challenges(expires_at);

CREATE TABLE IF NOT EXISTS request_nonces (
    principal_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    signature_created_at INTEGER NOT NULL,
    expires_at REAL NOT NULL,
    claimed_at REAL NOT NULL,
    PRIMARY KEY(principal_type, principal_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_request_nonces_expiry ON request_nonces(expires_at);

CREATE TABLE IF NOT EXISTS brokers (
    id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS broker_devices (
    id TEXT PRIMARY KEY,
    broker_id TEXT NOT NULL REFERENCES brokers(id),
    device_id TEXT NOT NULL REFERENCES devices(id),
    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
    approved_by_user_id TEXT NOT NULL REFERENCES users(id),
    runtime_version TEXT,
    protocol_version TEXT,
    build_commit TEXT,
    journal_pending INTEGER,
    heartbeat_at REAL,
    created_at REAL NOT NULL,
    revoked_at REAL,
    UNIQUE(broker_id, device_id)
);

CREATE TABLE IF NOT EXISTS broker_commands (
    id TEXT PRIMARY KEY,
    broker_device_id TEXT NOT NULL REFERENCES broker_devices(id),
    command_key TEXT,
    command_type TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL CHECK(state IN ('pending','completed','failed','expired')),
    result TEXT,
    created_at REAL NOT NULL,
    expires_at REAL,
    completed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_broker_commands_poll
    ON broker_commands(broker_device_id, state, created_at);

CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    founder_broker_id TEXT REFERENCES brokers(id),
    enrollment_policy TEXT NOT NULL DEFAULT '{}',
    key_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL CHECK(status IN ('active','archived')),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    role TEXT NOT NULL CHECK(role IN ('owner','admin','member')),
    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
    created_at REAL NOT NULL,
    revoked_at REAL,
    PRIMARY KEY(workspace_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id, status);

CREATE TABLE IF NOT EXISTS pools (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    policy TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK(status IN ('active','archived')),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(workspace_id, name)
);

CREATE TABLE IF NOT EXISTS workers (
    id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    manager_broker_id TEXT REFERENCES brokers(id),
    name TEXT NOT NULL,
    signing_public_key TEXT NOT NULL UNIQUE,
    encryption_public_key TEXT NOT NULL,
    certificate TEXT,
    executor_type TEXT NOT NULL,
    executor_version TEXT NOT NULL DEFAULT '',
    capabilities TEXT NOT NULL DEFAULT '{}',
    capacity INTEGER NOT NULL DEFAULT 1 CHECK(capacity > 0),
    status TEXT NOT NULL CHECK(status IN ('pending','active','offline','draining','revoked')),
    fencing_counter INTEGER NOT NULL DEFAULT 0,
    last_seen_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    revoked_at REAL
);
CREATE INDEX IF NOT EXISTS idx_workers_schedulable
    ON workers(status, executor_type, last_seen_at);

CREATE TABLE IF NOT EXISTS worker_maintenance_jobs (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL REFERENCES workers(id),
    broker_id TEXT NOT NULL REFERENCES brokers(id),
    issued_by_user_id TEXT NOT NULL REFERENCES users(id),
    issued_by_device_id TEXT NOT NULL REFERENCES devices(id),
    kind TEXT NOT NULL CHECK(kind IN ('worker_update','model_install')),
    spec TEXT NOT NULL,
    spec_digest TEXT NOT NULL,
    authorization TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'awaiting_upload','queued','leased','running','restarting',
        'succeeded','failed','cancelled','expired'
    )),
    progress TEXT NOT NULL DEFAULT '{}',
    result TEXT,
    fencing_token INTEGER NOT NULL DEFAULT 0,
    lease_session_id TEXT REFERENCES sessions(id),
    lease_expires_at REAL,
    heartbeat_at REAL,
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    completed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_worker_maintenance_poll
    ON worker_maintenance_jobs(worker_id, state, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_worker_maintenance_active_dedupe
    ON worker_maintenance_jobs(worker_id, dedupe_key)
    WHERE state IN ('awaiting_upload','queued','leased','running','restarting');

CREATE TABLE IF NOT EXISTS maintenance_artifacts (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE REFERENCES worker_maintenance_jobs(id),
    kind TEXT NOT NULL CHECK(kind='worker_update'),
    store_type TEXT NOT NULL,
    object_ref TEXT NOT NULL,
    expected_size INTEGER NOT NULL CHECK(expected_size > 0),
    expected_sha256 TEXT NOT NULL,
    observed_size INTEGER,
    observed_sha256 TEXT,
    state TEXT NOT NULL CHECK(state IN ('pending','uploaded','available','failed','deleted')),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_maintenance_artifacts_job
    ON maintenance_artifacts(job_id, state);

CREATE TABLE IF NOT EXISTS worker_allocations (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL REFERENCES workers(id),
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    pool_id TEXT NOT NULL REFERENCES pools(id),
    owner_consent_at REAL,
    workspace_approved_at REAL,
    approved_by_user_id TEXT REFERENCES users(id),
    allocation_proof TEXT,
    status TEXT NOT NULL CHECK(status IN ('offered','pending_owner','pending_workspace','active','revoked')),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    revoked_at REAL,
    UNIQUE(worker_id, pool_id)
);
CREATE INDEX IF NOT EXISTS idx_allocations_pool ON worker_allocations(pool_id, status);

CREATE TABLE IF NOT EXISTS enrollments (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('user','broker_device','worker','service','workspace_member','worker_allocation')),
    method TEXT NOT NULL CHECK(method IN ('direct_invite','invite_approval','apply_approval')),
    state TEXT NOT NULL CHECK(state IN ('issued','claimed','pending','active','expired','rejected','revoked')),
    workspace_id TEXT REFERENCES workspaces(id),
    pool_id TEXT REFERENCES pools(id),
    issuer_user_id TEXT REFERENCES users(id),
    subject_user_id TEXT REFERENCES users(id),
    subject_id TEXT,
    subject_key_fingerprint TEXT,
    scopes TEXT NOT NULL DEFAULT '[]',
    relationship TEXT,
    invite_secret_hash TEXT,
    claim TEXT,
    expires_at REAL,
    claimed_at REAL,
    decided_at REAL,
    decided_by_user_id TEXT REFERENCES users(id),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enrollments_workspace ON enrollments(workspace_id, state);

CREATE TABLE IF NOT EXISTS key_manifests (
    id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    manifest TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_user_id TEXT REFERENCES users(id),
    created_at REAL NOT NULL,
    revoked_at REAL,
    UNIQUE(subject_type, subject_id, key_version)
);

CREATE TABLE IF NOT EXISTS key_envelopes (
    id TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES workspaces(id),
    task_id TEXT,
    recipient_type TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    envelope TEXT NOT NULL,
    created_at REAL NOT NULL,
    revoked_at REAL
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    pool_id TEXT NOT NULL REFERENCES pools(id),
    consumer_user_id TEXT REFERENCES users(id),
    consumer_principal_type TEXT NOT NULL,
    consumer_principal_id TEXT NOT NULL,
    client_channel TEXT NOT NULL CHECK(client_channel IN ('api','cli','broker')),
    workflow_ref TEXT NOT NULL,
    workflow_digest TEXT NOT NULL,
    executor_type TEXT NOT NULL,
    public_requirements TEXT NOT NULL DEFAULT '{}',
    content_key_version INTEGER NOT NULL DEFAULT 1,
    encrypted_payload TEXT,
    reader_envelope TEXT,
    assigned_worker_id TEXT REFERENCES workers(id),
    reservation_expires_at REAL,
    state TEXT NOT NULL CHECK(state IN ('prepared','committed','queued','reserved','running','rekey_required','succeeded','failed','cancelled','expired')),
    priority INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    committed_at REAL,
    finished_at REAL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_queue
    ON tasks(pool_id, state, priority DESC, created_at);

CREATE TABLE IF NOT EXISTS task_attempts (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id),
    attempt_number INTEGER NOT NULL,
    worker_id TEXT NOT NULL REFERENCES workers(id),
    provider_user_id TEXT NOT NULL REFERENCES users(id),
    manager_broker_id TEXT REFERENCES brokers(id),
    executor_type TEXT NOT NULL,
    executor_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('reserved','leased','running','succeeded','failed','cancelled','expired')),
    responsibility TEXT CHECK(responsibility IN ('consumer','provider','platform','none')),
    failure_code INTEGER,
    safe_failure_details TEXT,
    progress TEXT NOT NULL DEFAULT '{}',
    rate_snapshot TEXT NOT NULL DEFAULT '{}',
    fencing_token INTEGER NOT NULL,
    reserved_at REAL NOT NULL,
    leased_at REAL,
    started_at REAL,
    finished_at REAL,
    UNIQUE(task_id, attempt_number),
    UNIQUE(worker_id, fencing_token)
);
CREATE INDEX IF NOT EXISTS idx_attempts_worker ON task_attempts(worker_id, state);

CREATE TABLE IF NOT EXISTS leases (
    id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES task_attempts(id),
    worker_id TEXT NOT NULL REFERENCES workers(id),
    fencing_token INTEGER NOT NULL,
    encrypted_tdk_envelope TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    heartbeat_at REAL,
    released_at REAL
);
CREATE INDEX IF NOT EXISTS idx_leases_active ON leases(worker_id, expires_at, released_at);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id),
    attempt_id TEXT REFERENCES task_attempts(id),
    kind TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('input','output')),
    store_type TEXT NOT NULL,
    object_ref TEXT NOT NULL,
    content_digest TEXT,
    encrypted_size INTEGER,
    media_metadata TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL CHECK(state IN ('pending','uploaded','available','failed','deleted')),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_cards (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL REFERENCES workers(id),
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    proposed_by_user_id TEXT NOT NULL REFERENCES users(id),
    approved_by_user_id TEXT REFERENCES users(id),
    rate_microtokens_per_gpu_second INTEGER NOT NULL CHECK(rate_microtokens_per_gpu_second >= 0),
    traffic_microtokens_per_gib INTEGER NOT NULL DEFAULT 0,
    formula_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL CHECK(status IN ('proposed','approved','rejected','superseded')),
    proposed_at REAL NOT NULL,
    decided_at REAL
);
CREATE INDEX IF NOT EXISTS idx_rates_lookup ON rate_cards(worker_id, workspace_id, status);

CREATE TABLE IF NOT EXISTS usage_events (
    id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES task_attempts(id),
    worker_id TEXT NOT NULL REFERENCES workers(id),
    event_kind TEXT NOT NULL,
    metrics TEXT NOT NULL,
    worker_signature TEXT,
    idempotency_key TEXT,
    observed_at REAL NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(attempt_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS usage_ledger (
    id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES task_attempts(id),
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
    reverses_ledger_id TEXT REFERENCES usage_ledger(id),
    reversal_reason_code TEXT CHECK(
        reversal_reason_code IS NULL OR reversal_reason_code IN (
            'duplicate_charge','rate_correction','provider_fault',
            'platform_fault','consumer_refund'
        )
    ),
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_attempt ON usage_ledger(attempt_id, created_at);

CREATE TABLE IF NOT EXISTS idempotency_records (
    principal_key TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_headers TEXT NOT NULL,
    response_body BLOB NOT NULL,
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY(principal_key, method, path, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_idempotency_records_expiry ON idempotency_records(expires_at);

CREATE TABLE IF NOT EXISTS transfer_ticket_uses (
    ticket_hash TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    used_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transfer_ticket_uses_age ON transfer_ticket_uses(used_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    workspace_id TEXT REFERENCES workspaces(id),
    action TEXT NOT NULL,
    subject_type TEXT,
    subject_id TEXT,
    safe_details TEXT NOT NULL DEFAULT '{}',
    request_id TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_workspace ON audit_events(workspace_id, created_at DESC);
"""


class GatewayDatabase:
    """Thread-safe SQLite connection and transaction boundary."""

    def __init__(self, path: str) -> None:
        absolute_path = os.path.abspath(path)
        parent = os.path.dirname(absolute_path)
        os.makedirs(parent, exist_ok=True)
        database_path = Path(absolute_path)
        if database_path.is_symlink():
            raise RuntimeError("gateway database path must not be a symbolic link")
        if not database_path.exists():
            descriptor = os.open(database_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
        elif os.name != "nt":
            os.chmod(database_path, 0o600)
        self.path = str(database_path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)
            # Additive v1 columns are migrated in place. This keeps SQLite
            # archives usable without weakening the single schema-version gate.
            task_columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(tasks)")}
            if "content_key_version" not in task_columns:
                self._conn.execute(
                    "ALTER TABLE tasks ADD COLUMN content_key_version INTEGER NOT NULL DEFAULT 1"
                )
            broker_command_columns = {
                row["name"] for row in self._conn.execute("PRAGMA table_info(broker_commands)")
            }
            if "command_key" not in broker_command_columns:
                self._conn.execute("ALTER TABLE broker_commands ADD COLUMN command_key TEXT")
            broker_device_columns = {
                row["name"] for row in self._conn.execute("PRAGMA table_info(broker_devices)")
            }
            for column, definition in (
                ("runtime_version", "TEXT"),
                ("protocol_version", "TEXT"),
                ("build_commit", "TEXT"),
                ("journal_pending", "INTEGER"),
                ("heartbeat_at", "REAL"),
            ):
                if column not in broker_device_columns:
                    self._conn.execute(
                        f"ALTER TABLE broker_devices ADD COLUMN {column} {definition}"
                    )
            usage_ledger_columns = {
                row["name"] for row in self._conn.execute("PRAGMA table_info(usage_ledger)")
            }
            if "reverses_ledger_id" not in usage_ledger_columns:
                self._conn.execute(
                    "ALTER TABLE usage_ledger ADD COLUMN reverses_ledger_id TEXT "
                    "REFERENCES usage_ledger(id)"
                )
            if "reversal_reason_code" not in usage_ledger_columns:
                self._conn.execute("ALTER TABLE usage_ledger ADD COLUMN reversal_reason_code TEXT")
            # The immutable ledger permits at most one correction for a charge.
            # A partial index keeps historical charge rows (whose reference is
            # NULL) unconstrained while making concurrent reversal requests safe.
            self._conn.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_one_reversal_per_charge
                   ON usage_ledger(reverses_ledger_id)
                   WHERE reverses_ledger_id IS NOT NULL"""
            )
            # One failed Attempt has one command globally, even when a User has
            # several Broker Devices.  Expired work may be reassigned without
            # allowing two devices to reserve replacement Workers concurrently.
            self._conn.execute("DROP INDEX IF EXISTS idx_broker_commands_key")
            self._conn.execute(
                """CREATE UNIQUE INDEX idx_broker_commands_key
                   ON broker_commands(command_key) WHERE command_key IS NOT NULL"""
            )
            row = self._conn.execute("SELECT version FROM schema_meta LIMIT 1").fetchone()
            if row is None:
                self._conn.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
            elif int(row["version"]) != SCHEMA_VERSION:
                raise RuntimeError(
                    f"unsupported gateway schema version {row['version']}; expected {SCHEMA_VERSION}"
                )

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield self._conn
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def execute(self, sql: str, args: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, args)

    def fetchone(self, sql: str, args: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, args).fetchone()

    def fetchall(self, sql: str, args: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, args))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def backup(self, output: Path, *, overwrite: bool = False) -> None:
        """Create a transactionally consistent online SQLite backup."""

        raw_destination = output.expanduser()
        if raw_destination.is_symlink():
            raise RuntimeError("backup path must not be a symbolic link")
        destination = raw_destination.resolve(strict=False)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"refusing to overwrite backup: {destination}")
        if destination.exists():
            destination.unlink()
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        target = sqlite3.connect(str(destination))
        try:
            with self._lock:
                self._conn.backup(target)
            target.execute("PRAGMA journal_mode=WAL")
            target.commit()
        finally:
            target.close()
        if os.name != "nt":
            os.chmod(destination, 0o600)

    def health(self, *, stamp: float | None = None) -> dict[str, Any]:
        row = self.fetchone("PRAGMA journal_mode")
        version = self.fetchone("SELECT version FROM schema_meta LIMIT 1")
        current_time = now() if stamp is None else stamp
        counts = {
            table: int(self.fetchone(f"SELECT COUNT(*) AS n FROM {table}")["n"])
            for table in ("users", "workspaces", "tasks")
        }
        worker_counts = self.fetchone(
            """SELECT COUNT(*) AS workers_total,
                      SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS workers_active,
                      SUM(CASE WHEN status='active' AND last_seen_at>? THEN 1 ELSE 0 END)
                          AS workers_online,
                      SUM(CASE WHEN status='revoked' THEN 1 ELSE 0 END) AS workers_revoked
               FROM workers""",
            (current_time - WORKER_ONLINE_WINDOW_SECONDS,),
        )
        counts.update(
            {
                key: int(worker_counts[key] or 0)
                for key in (
                    "workers_total",
                    "workers_active",
                    "workers_online",
                    "workers_revoked",
                )
            }
        )
        return {
            "ok": True,
            "schema_version": int(version["version"]),
            "journal_mode": str(row[0]).lower(),
            "counts": counts,
        }

    def bootstrap_operator(
        self,
        *,
        display_name: str,
        root_signing_public_key: str,
        root_encryption_public_key: str,
        device_id: str,
        device_name: str,
        device_signing_public_key: str,
        device_encryption_public_key: str,
        device_certificate: dict[str, Any],
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        stamp = now()
        with self.transaction(immediate=True) as conn:
            if conn.execute("SELECT 1 FROM users WHERE is_operator=1").fetchone():
                raise ValueError("operator_already_bootstrapped")
            user_id = new_id("usr")
            conn.execute(
                """INSERT INTO users
                   (id,display_name,root_signing_public_key,root_encryption_public_key,status,is_operator,created_at,updated_at)
                   VALUES (?,?,?,?, 'active',1,?,?)""",
                (
                    user_id,
                    display_name,
                    root_signing_public_key,
                    root_encryption_public_key,
                    stamp,
                    stamp,
                ),
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
        return (
            self.fetchone("SELECT * FROM users WHERE id=?", (user_id,)),
            self.fetchone("SELECT * FROM devices WHERE id=?", (device_id,)),
        )

    def create_session(
        self,
        *,
        principal_type: str,
        principal_id: str,
        user_id: str | None,
        scopes: list[str],
        ttl_seconds: int = 900,
    ) -> tuple[str, sqlite3.Row]:
        token = secrets.token_urlsafe(48)
        stamp = now()
        session_id = new_id("ses")
        self.execute(
            """INSERT INTO sessions
               (id,principal_type,principal_id,user_id,token_hash,scopes,expires_at,created_at,last_seen_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                session_id,
                principal_type,
                principal_id,
                user_id,
                hashlib.sha256(token.encode()).hexdigest(),
                json_text(scopes),
                stamp + ttl_seconds,
                stamp,
                stamp,
            ),
        )
        return token, self.fetchone("SELECT * FROM sessions WHERE id=?", (session_id,))

    def resolve_session(self, token: str) -> sqlite3.Row | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        stamp = now()
        row = self.fetchone(
            """SELECT * FROM sessions
               WHERE token_hash=? AND revoked_at IS NULL AND expires_at>?""",
            (digest, stamp),
        )
        if row:
            self.execute("UPDATE sessions SET last_seen_at=? WHERE id=?", (stamp, row["id"]))
        return row

    def claim_request_nonce(
        self,
        *,
        principal_type: str,
        principal_id: str,
        nonce: str,
        signature_created_at: int,
        ttl_seconds: int = 600,
    ) -> bool:
        stamp = now()
        with self.transaction(immediate=True) as conn:
            conn.execute("DELETE FROM request_nonces WHERE expires_at<=?", (stamp,))
            try:
                conn.execute(
                    """INSERT INTO request_nonces
                       (principal_type,principal_id,nonce,signature_created_at,expires_at,claimed_at)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        principal_type,
                        principal_id,
                        nonce,
                        signature_created_at,
                        stamp + ttl_seconds,
                        stamp,
                    ),
                )
            except sqlite3.IntegrityError:
                return False
            return True

    def prune_expired_security_state(self, *, stamp: float | None = None) -> dict[str, int]:
        """Bound short-lived authentication and replay-protection tables.

        Transfer-ticket uses remain longer than the maximum one-hour ticket
        lifetime before deletion. Expired sessions referenced by an active
        maintenance lease are retained until that lease is fenced or closed,
        preserving the existing foreign-key and fencing semantics.
        """

        cutoff = now() if stamp is None else stamp
        with self.transaction(immediate=True) as conn:
            conn.execute(
                """UPDATE worker_maintenance_jobs SET lease_session_id=NULL
                   WHERE state IN ('succeeded','failed','cancelled','expired')
                     AND lease_session_id IN (
                       SELECT id FROM sessions
                       WHERE expires_at<=?
                     )""",
                (cutoff,),
            )
            statements = {
                "device_recovery_challenges": (
                    "DELETE FROM device_recovery_challenges WHERE expires_at<=?",
                    (cutoff,),
                ),
                "auth_challenges": (
                    "DELETE FROM auth_challenges WHERE expires_at<=?",
                    (cutoff,),
                ),
                "service_auth_challenges": (
                    "DELETE FROM service_auth_challenges WHERE expires_at<=?",
                    (cutoff,),
                ),
                "request_nonces": (
                    "DELETE FROM request_nonces WHERE expires_at<=?",
                    (cutoff,),
                ),
                "idempotency_records": (
                    "DELETE FROM idempotency_records WHERE expires_at<=?",
                    (cutoff,),
                ),
                "sessions": (
                    """DELETE FROM sessions
                       WHERE expires_at<=?
                         AND NOT EXISTS (
                           SELECT 1 FROM worker_maintenance_jobs
                           WHERE lease_session_id=sessions.id
                         )""",
                    (cutoff,),
                ),
                "transfer_ticket_uses": (
                    "DELETE FROM transfer_ticket_uses WHERE used_at<=?",
                    (cutoff - TRANSFER_TICKET_REPLAY_RETENTION_SECONDS,),
                ),
            }
            deleted: dict[str, int] = {}
            for name, (sql, values) in statements.items():
                deleted[name] = max(0, conn.execute(sql, values).rowcount)
        return deleted

    def create_challenge(
        self, principal_type: str, principal_id: str, ttl_seconds: int = 120
    ) -> tuple[str, str]:
        challenge_id = new_id("chl")
        challenge = secrets.token_urlsafe(32)
        stamp = now()
        if principal_type == "service":
            self.execute(
                """INSERT INTO service_auth_challenges
                   (id,service_id,challenge_value,challenge_hash,expires_at,created_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    challenge_id,
                    principal_id,
                    challenge,
                    hashlib.sha256(challenge.encode()).hexdigest(),
                    stamp + ttl_seconds,
                    stamp,
                ),
            )
        else:
            self.execute(
                """INSERT INTO auth_challenges
                   (id,principal_type,principal_id,challenge_value,challenge_hash,expires_at,created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    challenge_id,
                    principal_type,
                    principal_id,
                    challenge,
                    hashlib.sha256(challenge.encode()).hexdigest(),
                    stamp + ttl_seconds,
                    stamp,
                ),
            )
        return challenge_id, challenge

    def get_challenge(
        self, challenge_id: str, principal_type: str, principal_id: str
    ) -> sqlite3.Row | None:
        if principal_type == "service":
            return self.fetchone(
                """SELECT * FROM service_auth_challenges
                   WHERE id=? AND service_id=?
                     AND consumed_at IS NULL AND expires_at>?""",
                (challenge_id, principal_id, now()),
            )
        return self.fetchone(
            """SELECT * FROM auth_challenges
               WHERE id=? AND principal_type=? AND principal_id=?
                 AND consumed_at IS NULL AND expires_at>?""",
            (challenge_id, principal_type, principal_id, now()),
        )

    def consume_challenge(self, challenge_id: str, principal_type: str, principal_id: str) -> bool:
        stamp = now()
        with self.transaction(immediate=True) as conn:
            if principal_type == "service":
                row = conn.execute(
                    """SELECT * FROM service_auth_challenges
                       WHERE id=? AND service_id=?
                         AND consumed_at IS NULL AND expires_at>?""",
                    (challenge_id, principal_id, stamp),
                ).fetchone()
                if row is None:
                    return False
                conn.execute(
                    "UPDATE service_auth_challenges SET consumed_at=? WHERE id=?",
                    (stamp, challenge_id),
                )
                return True
            row = conn.execute(
                """SELECT * FROM auth_challenges
                   WHERE id=? AND principal_type=? AND principal_id=?
                     AND consumed_at IS NULL AND expires_at>?""",
                (challenge_id, principal_type, principal_id, stamp),
            ).fetchone()
            if row is None:
                return False
            conn.execute(
                "UPDATE auth_challenges SET consumed_at=? WHERE id=?", (stamp, challenge_id)
            )
            return True

    def create_device_recovery_challenge(
        self, *, user_id: str, device_id: str, ttl_seconds: int = 120
    ) -> tuple[str, str]:
        challenge_id = new_id("chl")
        challenge = secrets.token_urlsafe(32)
        stamp = now()
        self.execute(
            """INSERT INTO device_recovery_challenges
               (id,user_id,device_id,challenge_value,challenge_hash,expires_at,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (
                challenge_id,
                user_id,
                device_id,
                challenge,
                hashlib.sha256(challenge.encode()).hexdigest(),
                stamp + ttl_seconds,
                stamp,
            ),
        )
        return challenge_id, challenge

    def get_device_recovery_challenge(
        self, *, challenge_id: str, user_id: str, device_id: str
    ) -> sqlite3.Row | None:
        return self.fetchone(
            """SELECT * FROM device_recovery_challenges
               WHERE id=? AND user_id=? AND device_id=?
                 AND consumed_at IS NULL AND expires_at>?""",
            (challenge_id, user_id, device_id, now()),
        )

    def consume_device_recovery_challenge(
        self, *, challenge_id: str, user_id: str, device_id: str
    ) -> bool:
        stamp = now()
        cursor = self.execute(
            """UPDATE device_recovery_challenges SET consumed_at=?
               WHERE id=? AND user_id=? AND device_id=?
                 AND consumed_at IS NULL AND expires_at>?""",
            (stamp, challenge_id, user_id, device_id, stamp),
        )
        return cursor.rowcount == 1

    def get_idempotency(
        self, principal: str, method: str, path: str, key: str
    ) -> sqlite3.Row | None:
        return self.fetchone(
            """SELECT * FROM idempotency_records
               WHERE principal_key=? AND method=? AND path=? AND idempotency_key=? AND expires_at>?""",
            (principal, method, path, key, now()),
        )

    def put_idempotency(
        self,
        principal: str,
        method: str,
        path: str,
        key: str,
        request_hash: str,
        status: int,
        headers: dict[str, str],
        body: bytes,
        ttl_seconds: int = 86_400,
    ) -> None:
        stamp = now()
        self.execute(
            """INSERT OR IGNORE INTO idempotency_records
               (principal_key,method,path,idempotency_key,request_hash,response_status,response_headers,response_body,expires_at,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                principal,
                method,
                path,
                key,
                request_hash,
                status,
                json_text(headers),
                body,
                stamp + ttl_seconds,
                stamp,
            ),
        )

    def claim_transfer_ticket(self, token: str, artifact_id: str) -> bool:
        try:
            self.execute(
                "INSERT INTO transfer_ticket_uses(ticket_hash,artifact_id,used_at) VALUES (?,?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), artifact_id, now()),
            )
        except sqlite3.IntegrityError:
            return False
        return True

    def audit(
        self,
        *,
        actor_type: str,
        actor_id: str,
        action: str,
        workspace_id: str | None = None,
        subject_type: str | None = None,
        subject_id: str | None = None,
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        self.execute(
            """INSERT INTO audit_events
               (id,actor_type,actor_id,workspace_id,action,subject_type,subject_id,safe_details,request_id,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                new_id("aud"),
                actor_type,
                actor_id,
                workspace_id,
                action,
                subject_type,
                subject_id,
                json_text(details or {}),
                request_id,
                now(),
            ),
        )


def row_dict(
    row: sqlite3.Row | None, *, json_columns: set[str] | None = None
) -> dict[str, Any] | None:
    if row is None:
        return None
    value = dict(row)
    for key in json_columns or set():
        if value.get(key) is not None:
            value[key] = json.loads(value[key])
    return value
