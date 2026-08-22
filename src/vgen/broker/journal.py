from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from platformdirs import user_state_path


class BrokerJournal:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or user_state_path("vgen") / "broker-journal.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise RuntimeError("broker journal path must not be a symbolic link")
        if not self.path.exists():
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
        elif os.name != "nt":
            os.chmod(self.path, 0o600)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at REAL NOT NULL,
                delivered_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_events_delivery
              ON events(delivered_at, created_at);
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )

    def append(self, kind: str, payload: dict[str, Any]) -> str:
        event_id = f"bev_{uuid.uuid4().hex}"
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO events(id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
                (event_id, kind, json.dumps(payload, separators=(",", ":")), time.time()),
            )
        return event_id

    def pending(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM events WHERE delivered_at IS NULL ORDER BY created_at LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "kind": row["kind"],
                "payload": json.loads(row["payload"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def mark_delivered(self, event_id: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE events SET delivered_at = ? WHERE id = ? AND delivered_at IS NULL",
                (time.time(), event_id),
            )

    def set_state(self, key: str, value: Any) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO state(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value, separators=(",", ":"))),
            )

    def get_state(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM state WHERE key = ?", (key,)
            ).fetchone()
        return default if row is None else json.loads(row["value"])

    def close(self) -> None:
        with self._lock:
            self._connection.close()
