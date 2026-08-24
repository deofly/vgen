from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from .profile import GatewayProfile

SignatureProvider = Callable[[str, str, bytes], Mapping[str, str]]
TokenRefresher = Callable[[], str]


def cli_exit_code(code: int, *, retry_action: str = "none") -> int:
    """Map a stable business-error category to the public CLI contract."""

    category = code // 10000
    if category in {10, 11, 12}:
        return 3
    if category in {20, 21, 22, 23, 24, 30, 31}:
        return 5 if retry_action != "none" else 4
    if category == 32:
        return 6
    if category == 34:
        return 5 if retry_action != "none" else 6
    if category in {33, 40}:
        return 7
    if category == 50:
        return 8
    if category == 60:
        return 5 if retry_action != "none" else 2
    if category == 70:
        return 5
    return 1


class VgenClientError(RuntimeError):
    def __init__(
        self,
        code: int,
        name: str,
        message: str,
        *,
        retry_action: str = "none",
        details: Mapping[str, Any] | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.name = name
        self.retry_action = retry_action
        self.details = dict(details or {})
        self.status_code = status_code

    @property
    def exit_code(self) -> int:
        return cli_exit_code(self.code, retry_action=self.retry_action)


class GatewayClient:
    def __init__(
        self,
        profile: GatewayProfile,
        *,
        session_token: str | None = None,
        signer: SignatureProvider | None = None,
        token_refresher: TokenRefresher | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.profile = profile
        self.session_token = session_token
        self.signer = signer
        self.token_refresher = token_refresher
        self.http = httpx.Client(
            base_url=profile.endpoint,
            timeout=httpx.Timeout(60, connect=10),
            follow_redirects=False,
            transport=transport,
            headers={"Vgen-Protocol-Version": "1", "Accept": "application/json"},
        )

    def close(self) -> None:
        self.http.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        params: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        auth: bool = True,
    ) -> Any:
        body = (
            b""
            if json_body is None
            else json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        headers: dict[str, str] = {"X-Request-ID": f"req_{uuid.uuid4().hex}"}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        response: httpx.Response | None = None
        for attempt in range(2):
            request_headers = dict(headers)
            if auth and self.session_token:
                request_headers["Authorization"] = f"Bearer {self.session_token}"
            try:
                request = self.http.build_request(
                    method,
                    path,
                    content=body if json_body is not None else None,
                    params=params,
                    headers=request_headers,
                )
                if auth and self.signer:
                    # RFC 9421 binds the exact request target, including a canonical
                    # query string. Sign the request only after httpx encoded params.
                    target = request.url.raw_path.decode("ascii")
                    request.headers.update(self.signer(method.upper(), target, body))
                response = self.http.send(request)
            except httpx.RequestError as exc:
                raise VgenClientError(
                    700001,
                    "GATEWAY_UNREACHABLE",
                    f"Gateway is unreachable: {exc}",
                    retry_action="later",
                ) from None
            if (
                attempt == 0
                and auth
                and self.token_refresher is not None
                and self._error_code(response) == 100002
            ):
                self.session_token = self.token_refresher()
                continue
            break
        if response is None:  # defensive invariant; the loop always sends at least once
            raise RuntimeError("Gateway request completed without a response.")
        if response.is_success:
            return response.json() if response.content else None
        self._raise_error(response)

    @staticmethod
    def _error_code(response: httpx.Response) -> int | None:
        try:
            return int(response.json().get("error", {}).get("code"))
        except (ValueError, TypeError, AttributeError):
            return None

    @staticmethod
    def _raise_error(response: httpx.Response) -> None:
        try:
            envelope = response.json().get("error", {})
        except (ValueError, AttributeError):
            envelope = {}
        retry = envelope.get("retry") or {}
        raise VgenClientError(
            int(envelope.get("code") or 900001),
            str(envelope.get("name") or "INTERNAL_ERROR"),
            str(envelope.get("message") or f"Gateway returned HTTP {response.status_code}"),
            retry_action=str(retry.get("action") or "none"),
            details=envelope.get("details") if isinstance(envelope.get("details"), dict) else None,
            status_code=response.status_code,
        )

    def health(self) -> Any:
        return self.request("GET", "/healthz", auth=False)

    def status(self) -> Any:
        return self.request("GET", "/api/v1/status")

    def create_workspace(self, payload: Mapping[str, Any]) -> Any:
        return self.request(
            "POST",
            "/api/v1/workspaces",
            json_body=payload,
            idempotency_key=f"workspace:{uuid.uuid4()}",
        )

    def create_pool(self, workspace_id: str, payload: Mapping[str, Any]) -> Any:
        return self.request(
            "POST",
            f"/api/v1/workspaces/{workspace_id}/pools",
            json_body=payload,
            idempotency_key=f"pool:{uuid.uuid4()}",
        )

    def prepare_task(self, payload: Mapping[str, Any], idempotency_key: str) -> Any:
        return self.request(
            "POST",
            "/api/v1/tasks/prepare",
            json_body=payload,
            idempotency_key=idempotency_key,
        )

    def preflight_task(self, payload: Mapping[str, Any]) -> Any:
        # This endpoint deliberately has no Idempotency-Key: it does not create
        # a Task, reserve capacity, advance fencing, or write usage records.
        return self.request("POST", "/api/v1/tasks/preflight", json_body=payload)

    def commit_task(self, task_id: str, payload: Mapping[str, Any]) -> Any:
        return self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/commit",
            json_body=payload,
            idempotency_key=f"commit:{task_id}",
        )

    def get_task(self, task_id: str) -> Any:
        return self.request("GET", f"/api/v1/tasks/{task_id}")

    def list_tasks(self, *, workspace_id: str | None = None, limit: int = 100) -> Any:
        params: dict[str, Any] = {"limit": limit}
        if workspace_id:
            params["workspace_id"] = workspace_id
        return self.request("GET", "/api/v1/tasks", params=params)

    def list_task_page(
        self,
        *,
        workspace_id: str,
        limit: int = 20,
        cursor: str | None = None,
        state: str | None = None,
        sort: str = "created",
        order: str = "desc",
    ) -> Any:
        params: dict[str, Any] = {
            "workspace_id": workspace_id,
            "limit": limit,
            "sort": sort,
            "order": order,
        }
        if cursor:
            params["cursor"] = cursor
        if state:
            params["state"] = state
        return self.request("GET", "/api/v1/tasks/page", params=params)

    def close_task(self, task_id: str) -> Any:
        return self.request(
            "POST",
            f"/api/v1/tasks/{task_id}/cancel",
            json_body={},
            idempotency_key=f"cancel:{task_id}",
        )

    def set_worker_manager(self, worker_id: str, broker_id: str | None) -> Any:
        return self.request(
            "POST",
            f"/api/v1/workers/{worker_id}/manager",
            json_body={"broker_id": broker_id},
            idempotency_key=f"worker-manager:{worker_id}:{broker_id or 'none'}",
        )

    def create_worker_maintenance(
        self,
        *,
        broker_id: str,
        worker_id: str,
        spec: Mapping[str, Any],
        authorization: Mapping[str, Any],
        idempotency_key: str,
    ) -> Any:
        return self.request(
            "POST",
            f"/api/v1/brokers/{broker_id}/workers/{worker_id}/maintenance-jobs",
            json_body={"spec": dict(spec), "authorization": dict(authorization)},
            idempotency_key=idempotency_key,
        )

    def commit_worker_maintenance(self, job_id: str) -> Any:
        return self.request(
            "POST",
            f"/api/v1/maintenance-jobs/{job_id}/commit",
            json_body={},
            idempotency_key=f"maintenance-commit:{job_id}",
        )

    def list_worker_maintenance(self, worker_id: str) -> Any:
        return self.request("GET", f"/api/v1/workers/{worker_id}/maintenance-jobs")

    def get_worker_maintenance(self, job_id: str) -> Any:
        return self.request("GET", f"/api/v1/maintenance-jobs/{job_id}")

    def cancel_worker_maintenance(self, job_id: str) -> Any:
        return self.request(
            "POST",
            f"/api/v1/maintenance-jobs/{job_id}/cancel",
            json_body={},
            idempotency_key=f"maintenance-cancel:{job_id}",
        )
