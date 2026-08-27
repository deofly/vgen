from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import AsyncIterable

from fastapi.testclient import TestClient
from starlette.requests import Request

from tests.gateway.test_gateway_api import bootstrap
from vgen.gateway.app import _cache_bounded_body, _TokenBucketRateLimiter, create_app
from vgen.gateway.artifacts import TransferTicket, VerifiedTicket
from vgen.gateway.database import GatewayDatabase
from vgen.protocol.ids import new_id


class RecordingArtifactStore:
    store_type = "local"

    def __init__(self, *, max_bytes: int = 4096) -> None:
        self.max_bytes = max_bytes
        self.uploaded = bytearray()

    def verify_ticket(self, token: str, *, method: str) -> VerifiedTicket:
        assert token == "reviewed-ticket"
        return VerifiedTicket(self.artifact_id, method.upper(), time.time() + 60, self.max_bytes)

    async def put_chunks(
        self, artifact_id: str, chunks: AsyncIterable[bytes], *, max_bytes: int
    ) -> tuple[int, str]:
        assert artifact_id == self.artifact_id
        assert max_bytes == self.max_bytes
        async for chunk in chunks:
            self.uploaded.extend(chunk)
        assert len(self.uploaded) <= max_bytes
        return len(self.uploaded), hashlib.sha256(self.uploaded).hexdigest()

    def issue_ticket(
        self, artifact_id: str, *, method: str, ttl_seconds: int, max_bytes: int
    ) -> TransferTicket:
        raise AssertionError("not used")

    def put(self, artifact_id, stream, *, max_bytes):  # type: ignore[no-untyped-def]
        raise AssertionError("not used")

    def open(self, artifact_id):  # type: ignore[no-untyped-def]
        raise AssertionError("not used")

    def observe_upload(self, artifact_id, *, max_bytes):  # type: ignore[no-untyped-def]
        raise AssertionError("not used")


def _app(tmp_path, **overrides):  # type: ignore[no-untyped-def]
    return create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
        **overrides,
    )


def test_control_body_limit_rejects_declared_and_chunked_overflow(tmp_path) -> None:
    app = _app(tmp_path, max_control_body_bytes=32)
    headers = {"Vgen-Protocol-Version": "1"}
    with TestClient(app) as client:
        declared = client.post(
            "/api/v1/auth/enroll",
            headers=headers,
            content=b"x" * 33,
        )
        assert declared.status_code == 413
        assert declared.json()["error"]["name"] == "REQUEST_BODY_TOO_LARGE"

        def chunks():
            yield b"x" * 16
            yield b"y" * 17

        chunked = client.post(
            "/api/v1/auth/enroll",
            headers=headers,
            content=chunks(),
        )
        assert chunked.status_code == 413
        assert chunked.json()["error"]["details"] == {"max_bytes": 32}


def test_control_body_limit_counts_actual_bytes_when_length_is_misleading(tmp_path) -> None:
    app = _app(tmp_path, max_control_body_bytes=32)

    def chunks():
        yield b"x" * 20
        yield b"y" * 20

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/enroll",
            headers={"Vgen-Protocol-Version": "1", "Content-Length": "1"},
            content=chunks(),
        )
    assert response.status_code == 413
    assert response.json()["error"]["name"] == "REQUEST_BODY_TOO_LARGE"


def test_default_public_auth_body_limit_is_exactly_64_kib(tmp_path) -> None:
    app = _app(tmp_path)
    protocol = {"Vgen-Protocol-Version": "1"}

    def over_limit_chunks():
        yield b"x" * 32_768
        yield b"y" * 32_769

    with TestClient(app) as client:
        at_limit = client.post(
            "/api/v1/auth/bootstrap",
            headers=protocol,
            content=b"x" * 65_536,
        )
        declared = client.post(
            "/api/v1/auth/bootstrap",
            headers=protocol,
            content=b"x" * 65_537,
        )
        chunked = client.post(
            "/api/v1/auth/bootstrap",
            headers=protocol,
            content=over_limit_chunks(),
        )
        misleading = client.post(
            "/api/v1/auth/bootstrap",
            headers={**protocol, "Content-Length": "1"},
            content=over_limit_chunks(),
        )

    assert at_limit.status_code != 413
    for response in (declared, chunked, misleading):
        assert response.status_code == 413
        assert response.json()["error"]["details"] == {"max_bytes": 65_536}


def test_control_body_cache_handles_many_tiny_asgi_chunks_with_one_byte_buffer() -> None:
    remaining = 50_000

    async def receive():
        nonlocal remaining
        remaining -= 1
        return {
            "type": "http.request",
            "body": b"x",
            "more_body": remaining > 0,
        }

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/tasks/prepare",
            "headers": [],
        },
        receive,
    )
    assert asyncio.run(_cache_bounded_body(request, max_bytes=50_000))
    assert asyncio.run(request.body()) == b"x" * 50_000


def test_default_control_limit_allows_large_key_metadata_but_rejects_over_16_mib(tmp_path) -> None:
    app = _app(tmp_path)
    legal_metadata = b'{"padding":"' + b"x" * (2 * 1024**2) + b'"}'
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        _, headers = bootstrap(client)
        accepted_by_body_guard = client.post(
            "/api/v1/workspaces/wsp_example/key-rotations",
            headers=headers,
            content=legal_metadata,
        )
        over_limit = client.post(
            "/api/v1/workspaces/wsp_example/key-rotations",
            headers={**headers, "Content-Length": str(16 * 1024**2 + 1)},
            content=b"{}",
        )
    # The route can still reject unauthenticated or malformed metadata; the
    # abuse guard must not mistake a legal multi-envelope payload for a 413.
    assert accepted_by_body_guard.status_code != 413
    assert over_limit.status_code == 413
    assert over_limit.json()["error"]["details"] == {"max_bytes": 16 * 1024**2}


def test_artifact_transfer_is_streamed_outside_control_body_limit(tmp_path) -> None:
    store = RecordingArtifactStore(max_bytes=512)
    store.artifact_id = new_id("artifact")
    app = _app(
        tmp_path,
        max_control_body_bytes=16,
        artifact_store_override=store,
    )
    # This test isolates the HTTP/stream boundary; artifact repository state is
    # covered by the task and maintenance integration tests.
    app.state.repository.mark_artifact_uploaded = lambda **_values: None

    def chunks():
        for _ in range(4):
            yield b"reviewed-stream" * 8

    with TestClient(app) as client:
        response = client.put(
            f"/api/v1/artifacts/transfer/{store.artifact_id}",
            headers={"Vgen-Artifact-Ticket": "reviewed-ticket"},
            content=chunks(),
        )
    assert response.status_code == 204
    assert len(store.uploaded) == len(b"reviewed-stream") * 32
    assert len(store.uploaded) > 16


def test_artifact_declared_length_cannot_exceed_signed_ticket(tmp_path) -> None:
    store = RecordingArtifactStore(max_bytes=10)
    store.artifact_id = new_id("artifact")
    app = _app(tmp_path, artifact_store_override=store)
    app.state.repository.mark_artifact_uploaded = lambda **_values: None
    with TestClient(app) as client:
        response = client.put(
            f"/api/v1/artifacts/transfer/{store.artifact_id}",
            headers={"Vgen-Artifact-Ticket": "reviewed-ticket"},
            content=b"x" * 11,
        )
        used = app.state.db.fetchone("SELECT COUNT(*) AS n FROM transfer_ticket_uses")
    assert response.status_code == 413
    assert used["n"] == 0
    assert not store.uploaded


def test_public_auth_rate_limit_returns_bounded_429_and_ignores_spoofed_forwarding(tmp_path) -> None:
    app = _app(tmp_path)
    with TestClient(app) as client:
        responses = [
            client.post(
                "/api/v1/auth/bootstrap",
                headers={
                    "Vgen-Protocol-Version": "1",
                    "X-Forwarded-For": f"203.0.113.{index}",
                },
                json={},
            )
            for index in range(6)
        ]
    assert all(response.status_code == 422 for response in responses[:5])
    limited = responses[-1]
    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "12"
    assert limited.headers["Cache-Control"] == "no-store"
    assert limited.json()["error"]["name"] == "RATE_LIMITED"
    assert limited.json()["error"]["retry"] == {
        "allowed": True,
        "action": "later",
        "after_ms": 12_000,
    }


def test_token_bucket_memory_is_bounded_and_idle_entries_are_pruned() -> None:
    stamp = [100.0]
    limiter = _TokenBucketRateLimiter(
        max_buckets=3,
        idle_seconds=10,
        clock=lambda: stamp[0],
    )
    for index in range(20):
        allowed, _ = limiter.check(
            "auth", f"client-{index}", capacity=1, refill_per_second=1
        )
        assert allowed
    assert limiter.bucket_count == 3
    stamp[0] += 11
    limiter.check("auth", "fresh-client", capacity=1, refill_per_second=1)
    assert limiter.bucket_count == 1


def test_expired_security_records_are_pruned_without_breaking_active_lease_fk(tmp_path) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    cutoff = 10_000.0
    expired = cutoff - 1
    old_ticket = cutoff - 7_201
    with db.transaction(immediate=True) as conn:
        conn.execute(
            "INSERT INTO users VALUES ('usr_test','User','root-sign','root-enc','active',1,1,1)"
        )
        conn.execute(
            """INSERT INTO devices
               VALUES ('dev_test','usr_test','Device','dev-sign','dev-enc','{}','active',1,1,NULL)"""
        )
        conn.execute(
            "INSERT INTO workspaces VALUES ('wsp_test','Workspace','usr_test',NULL,'{}',1,'active',1,1)"
        )
        conn.execute(
            """INSERT INTO services
               VALUES ('svc_test','wsp_test','Service','svc-sign','svc-enc','[]','active','usr_test',1,1,NULL)"""
        )
        conn.execute(
            "INSERT INTO brokers VALUES ('brk_test','usr_test','Broker','active',1,1)"
        )
        conn.execute(
            """INSERT INTO workers
               (id,owner_user_id,name,signing_public_key,encryption_public_key,
                executor_type,executor_version,capabilities,capacity,status,created_at,updated_at)
               VALUES ('wrk_test','usr_test','Worker','wrk-sign','wrk-enc','comfyui','1','{}',1,
                       'active',1,1)"""
        )
        for session_id in ("ses_free", "ses_active_fk", "ses_terminal_fk"):
            conn.execute(
                """INSERT INTO sessions
                   VALUES (?,'worker','wrk_test','usr_test',?,'[]',?,NULL,1,1)""",
                (session_id, f"hash-{session_id}", expired),
            )
        for job_id, state, session_id, dedupe in (
            ("mtj_active", "queued", "ses_active_fk", "active"),
            ("mtj_terminal", "succeeded", "ses_terminal_fk", "terminal"),
        ):
            conn.execute(
                """INSERT INTO worker_maintenance_jobs
                   (id,worker_id,broker_id,issued_by_user_id,issued_by_device_id,kind,spec,
                    spec_digest,authorization,dedupe_key,state,progress,fencing_token,
                    lease_session_id,expires_at,created_at,updated_at)
                   VALUES (?,'wrk_test','brk_test','usr_test','dev_test','model_install','{}',
                           'digest','{}',?,?,'{}',1,?,?,1,1)""",
                (job_id, dedupe, state, session_id, cutoff + 100),
            )
        conn.execute(
            """INSERT INTO auth_challenges
               VALUES ('chl_auth','worker','wrk_test','value','hash',?,NULL,1)""",
            (expired,),
        )
        conn.execute(
            """INSERT INTO service_auth_challenges
               VALUES ('chl_service','svc_test','value','hash',?,NULL,1)""",
            (expired,),
        )
        conn.execute(
            """INSERT INTO device_recovery_challenges
               VALUES ('chl_recovery','usr_test','dev_new','value','hash',?,NULL,1)""",
            (expired,),
        )
        conn.execute(
            "INSERT INTO request_nonces VALUES ('worker','wrk_test','nonce',1,?,1)",
            (expired,),
        )
        conn.execute(
            """INSERT INTO idempotency_records
               VALUES ('principal','POST','/path','key','hash',200,'{}',X'',?,1)""",
            (expired,),
        )
        conn.execute(
            "INSERT INTO transfer_ticket_uses VALUES ('old','art_old',?)", (old_ticket,)
        )
        conn.execute(
            "INSERT INTO transfer_ticket_uses VALUES ('recent','art_recent',?)", (cutoff - 1,)
        )

    deleted = db.prune_expired_security_state(stamp=cutoff)

    assert deleted == {
        "device_recovery_challenges": 1,
        "auth_challenges": 1,
        "service_auth_challenges": 1,
        "request_nonces": 1,
        "idempotency_records": 1,
        "maintenance_intent_receipts": 0,
        "sessions": 2,
        "transfer_ticket_uses": 1,
    }
    assert db.fetchone("SELECT id FROM sessions WHERE id='ses_active_fk'") is not None
    terminal = db.fetchone(
        "SELECT lease_session_id FROM worker_maintenance_jobs WHERE id='mtj_terminal'"
    )
    assert terminal["lease_session_id"] is None
    assert db.fetchone("SELECT ticket_hash FROM transfer_ticket_uses")["ticket_hash"] == "recent"
    db.close()
