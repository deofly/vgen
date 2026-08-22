from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from platformdirs import user_config_path


class ProfileError(ValueError):
    pass


@dataclass(frozen=True)
class GatewayProfile:
    name: str
    endpoint: str
    gateway_id: str | None = None
    user_id: str | None = None
    device_id: str | None = None
    default_workspace: str | None = None
    default_pool: str | None = None
    # New-User and existing-User Workspace joins are staged here until both
    # membership and a decryptable Workspace key envelope are available.  A
    # staged join must not make task commands treat an unusable Workspace as
    # the default; an existing usable default remains active until completion.
    pending_workspace: str | None = None
    pending_enrollment: str | None = None
    home_broker_id: str | None = None
    home_broker_device_id: str | None = None
    key_ref: str | None = None
    principal_type: Literal["device", "service"] = "device"
    service_id: str | None = None
    service_key_ref: str | None = None
    service_credentials_file: str | None = None

    def __post_init__(self) -> None:
        if not self.name or any(character.isspace() for character in self.name):
            raise ProfileError("profile name must be non-empty and contain no whitespace")
        endpoint = self.endpoint.rstrip("/")
        try:
            parsed = urlsplit(endpoint)
            # Accessing port performs urllib's range and syntax validation.
            _ = parsed.port
        except ValueError as exc:
            raise ProfileError("profile endpoint is not a valid URL") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ProfileError(
                "profile endpoint must be an origin URL without credentials, path, query, or fragment"
            )
        localhost = parsed.hostname.lower() in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme != "https" and not localhost:
            raise ProfileError("profile endpoint must use HTTPS except for localhost")
        if self.principal_type not in {"device", "service"}:
            raise ProfileError("profile principal type must be device or service")
        if self.principal_type == "service":
            if not self.service_id:
                raise ProfileError("a Service profile requires a Service ID")
            if bool(self.service_key_ref) == bool(self.service_credentials_file):
                raise ProfileError(
                    "a Service profile requires exactly one keyring account or credential file"
                )
        object.__setattr__(self, "endpoint", endpoint)


class ProfileStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or user_config_path("vgen") / "profiles.yaml"

    def load(self) -> tuple[str | None, dict[str, GatewayProfile]]:
        if not self.path.exists():
            return None, {}
        raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict) or raw.get("schema_version") != 1:
            raise ProfileError("unsupported profile file")
        profiles = {
            name: GatewayProfile(name=name, **values)
            for name, values in (raw.get("profiles") or {}).items()
        }
        current = raw.get("current")
        if current is not None and current not in profiles:
            raise ProfileError("current profile does not exist")
        return current, profiles

    def get(self, name: str | None = None) -> GatewayProfile:
        current, profiles = self.load()
        selected = name or current
        if not selected or selected not in profiles:
            raise ProfileError("no Gateway profile selected; run `vgen profile add`")
        return profiles[selected]

    def put(self, profile: GatewayProfile, *, make_current: bool = True) -> None:
        current, profiles = self.load()
        profiles[profile.name] = profile
        self._save(profile.name if make_current else current, profiles)

    def use(self, name: str) -> None:
        _, profiles = self.load()
        if name not in profiles:
            raise ProfileError(f"profile does not exist: {name}")
        self._save(name, profiles)

    def update_binding(self, name: str, **updates: Any) -> GatewayProfile:
        current, profiles = self.load()
        if name not in profiles:
            raise ProfileError(f"profile does not exist: {name}")
        values = asdict(profiles[name])
        values.update(updates)
        values.pop("name", None)
        profile = GatewayProfile(name=name, **values)
        profiles[name] = profile
        self._save(current, profiles)
        return profile

    def _save(self, current: str | None, profiles: dict[str, GatewayProfile]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = {
            "schema_version": 1,
            "current": current,
            "profiles": {
                name: {key: value for key, value in asdict(profile).items() if key != "name"}
                for name, profile in sorted(profiles.items())
            },
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(self.path)
