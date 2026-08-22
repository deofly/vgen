from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

from vgen.cli.client import GatewayClient, VgenClientError

from .journal import BrokerJournal

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BrokerDaemonConfig:
    broker_id: str
    device_id: str
    poll_seconds: float = 5.0


class BrokerDaemon:
    """Local key/rekey agent.

    The daemon deliberately has no task queue. Gateway remains authoritative;
    this process only heartbeats a Broker Device and durably executes delegated
    management commands such as task-key rewrapping.
    """

    def __init__(
        self,
        config: BrokerDaemonConfig,
        client: GatewayClient,
        journal: BrokerJournal | None = None,
        command_handler: Any | None = None,
    ) -> None:
        self.config = config
        self.client = client
        self.journal = journal or BrokerJournal()
        self.command_handler = command_handler
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self, *, once: bool = False) -> None:
        while not self._stop.is_set():
            self.run_once()
            if once:
                return
            self._stop.wait(self.config.poll_seconds)

    def run_once(self) -> None:
        payload = {
            "broker_id": self.config.broker_id,
            "status": "online",
            "journal_pending": len(self.journal.pending()),
        }
        try:
            self.client.request(
                "POST",
                f"/api/v1/broker-devices/{self.config.device_id}/heartbeat",
                json_body=payload,
                idempotency_key=f"heartbeat:{self.config.device_id}:{int(time.time())}",
            )
            commands = self.client.request(
                "GET",
                f"/api/v1/broker-devices/{self.config.device_id}/commands",
                params={"after": self.journal.get_state("last_command", "")},
            )
        except VgenClientError as exc:
            self.journal.append(
                "gateway_error",
                {"code": exc.code, "name": exc.name, "retry_action": exc.retry_action},
            )
            logger.warning("Gateway command poll failed: %s", exc)
            return
        for command in commands.get("items", []) if isinstance(commands, dict) else []:
            # Preserve command order.  Advancing past a failed command would
            # make the Gateway cursor hide it permanently on this device.
            if not self._execute(command):
                break

    def _execute(self, command: dict[str, Any]) -> bool:
        command_id = str(command.get("id") or "")
        if not command_id:
            return False
        try:
            result = (
                self.command_handler(command)
                if self.command_handler is not None
                else {"status": "unsupported"}
            )
            self.client.request(
                "POST",
                f"/api/v1/broker-devices/{self.config.device_id}/commands/{command_id}/complete",
                json_body={"result": result},
                idempotency_key=f"broker-command:{command_id}",
            )
            self.journal.set_state("last_command", command_id)
            return True
        except Exception as exc:  # command is journaled without secret detail
            self.journal.append(
                "command_failed", {"command_id": command_id, "error_type": type(exc).__name__}
            )
            return False
