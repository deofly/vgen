from __future__ import annotations

import stat
from typing import Any

from vgen.broker.daemon import BrokerDaemon, BrokerDaemonConfig
from vgen.broker.journal import BrokerJournal


def test_broker_journal_is_durable(tmp_path) -> None:
    path = tmp_path / "journal.db"
    journal = BrokerJournal(path)
    event_id = journal.append("rekey", {"task_id": "tsk_1"})
    journal.set_state("cursor", "cmd_1")
    journal.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    reopened = BrokerJournal(path)
    assert reopened.pending()[0]["id"] == event_id
    assert reopened.get_state("cursor") == "cmd_1"
    reopened.mark_delivered(event_id)
    assert reopened.pending() == []


class CommandClient:
    def __init__(self) -> None:
        self.completed: list[str] = []
        self.heartbeats: list[dict[str, Any]] = []

    def request(self, method: str, path: str, *, json_body: Any = None, **_: Any) -> dict[str, Any]:
        if method == "GET":
            return {
                "items": [
                    {"id": "bcm_first", "command_type": "task_rekey", "payload": {}},
                    {"id": "bcm_second", "command_type": "task_rekey", "payload": {}},
                ]
            }
        if path.endswith("/heartbeat"):
            self.heartbeats.append(json_body)
        if path.endswith("/complete"):
            self.completed.append(path.split("/")[-2])
        return {"ok": True}


def test_broker_does_not_advance_cursor_past_failed_command(tmp_path) -> None:
    client = CommandClient()
    journal = BrokerJournal(tmp_path / "journal.db")

    def fail_first(command: dict[str, Any]) -> dict[str, Any]:
        if command["id"] == "bcm_first":
            raise RuntimeError("safe failure")
        return {"status": "done"}

    daemon = BrokerDaemon(
        BrokerDaemonConfig("brk_test", "bdev_test"),
        client,  # type: ignore[arg-type]
        journal=journal,
        command_handler=fail_first,
    )
    daemon.run_once()

    assert client.heartbeats == [
        {
            "broker_id": "brk_test",
            "status": "online",
            "runtime_version": daemon.config.runtime_version,
            "protocol_version": "1",
            "build_commit": daemon.config.build_commit,
            "journal_pending": 0,
        }
    ]
    assert client.completed == []
    assert journal.get_state("last_command") is None
    assert journal.pending()[0]["payload"] == {
        "command_id": "bcm_first",
        "error_type": "RuntimeError",
    }
    journal.close()
