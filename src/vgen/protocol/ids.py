"""Opaque resource identifiers used by the v1 protocol."""

from __future__ import annotations

import base64
import re
import secrets
from collections.abc import Mapping
from types import MappingProxyType

ID_PREFIXES: Mapping[str, str] = MappingProxyType(
    {
        "request": "req",
        "user": "usr",
        "device": "dev",
        "broker": "brk",
        "broker_device": "bdev",
        "broker_command": "bcm",
        "workspace": "wsp",
        "membership": "mem",
        "pool": "pol",
        "worker": "wrk",
        "worker_maintenance_job": "mtj",
        "allocation": "wal",
        "invite": "inv",
        "application": "app",
        "enrollment": "enr",
        "session": "ses",
        "task": "tsk",
        "attempt": "atm",
        "lease": "lse",
        "artifact": "art",
        "workflow": "wfl",
        "workflow_release": "wfr",
        "usage_event": "use",
        "usage_ledger": "uld",
        "rate_card": "rtc",
        "key_manifest": "kmf",
        "key_envelope": "ken",
        "audit_event": "aud",
        "service": "svc",
    }
)

_VALID_PREFIXES = frozenset(ID_PREFIXES.values())
_ID_PATTERN = re.compile(r"^(?P<prefix>[a-z][a-z0-9]{2,4})_(?P<body>[a-z2-7]{26})$")


def new_id(kind: str) -> str:
    """Return a random 128-bit, URL-safe ID with a human-readable prefix."""

    try:
        prefix = ID_PREFIXES[kind]
    except KeyError as exc:
        raise ValueError(f"unknown resource ID kind: {kind}") from exc
    body = base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=").lower()
    return f"{prefix}_{body}"


def validate_id(value: str, kind: str | None = None) -> bool:
    """Return whether *value* is a canonical VGen ID, optionally of *kind*."""

    match = _ID_PATTERN.fullmatch(value)
    if match is None or match.group("prefix") not in _VALID_PREFIXES:
        return False
    if kind is None:
        return True
    try:
        expected = ID_PREFIXES[kind]
    except KeyError as exc:
        raise ValueError(f"unknown resource ID kind: {kind}") from exc
    return match.group("prefix") == expected
