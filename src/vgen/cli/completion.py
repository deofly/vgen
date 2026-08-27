from __future__ import annotations

import argparse
import json
import os
import shlex
import tempfile
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import argcomplete
import yaml
from argcomplete.completers import DirectoriesCompleter, FilesCompleter
from platformdirs import user_cache_path

from vgen.market import WorkflowRegistry
from vgen.market.registry import RegistryError

from .profile import ProfileError, ProfileStore

SUPPORTED_SHELLS = ("bash", "zsh")
MANAGED_BLOCK_START = "# >>> vgen shell completion >>>"
MANAGED_BLOCK_END = "# <<< vgen shell completion <<<"
COMPLETION_CACHE_TTL_SECONDS = 300.0
COMPLETION_CACHE_SCHEMA_VERSION = 1
COMPLETION_CACHE_KINDS = frozenset({"workers", "workspaces", "tasks"})
MAX_COMPLETION_CACHE_BYTES = 2 * 1024 * 1024

_FILE_ARGUMENTS = frozenset(
    {
        "bootstrap_code_file",
        "comfy_policy_file",
        "credentials_file",
        "dangerously_export_recovery",
        "identity_file",
        "image",
        "index",
        "key_file",
        "last_image",
        "output",
        "private_key_file",
        "recovery_file",
        "session_token_file",
        "source",
        "wheel",
        "workflow_package",
    }
)
_DIRECTORY_ARGUMENTS = frozenset(
    {
        "comfy_model_root",
        "comfy_output_dir",
        "local_artifact_root",
        "output_dir",
        "work_root",
    }
)


def shell_completion(shell: str) -> str:
    if shell not in SUPPORTED_SHELLS:
        raise ValueError(f"unsupported shell: {shell}")
    # The third positional argument selects argcomplete's renderer; this call
    # never starts a process. Positional form also avoids conflating the
    # library's ``shell`` parameter with subprocess ``shell=True``.
    return argcomplete.shellcode(["vgen"], True, shell).rstrip() + "\n"


def _completion_cache_path() -> Path:
    return user_cache_path("vgen") / "completion-values.json"


def _safe_completion_value(value: object) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip()
    if (
        not candidate
        or len(candidate) > 256
        or any(not character.isprintable() for character in candidate)
    ):
        return None
    return candidate


def _read_completion_cache(path: Path) -> dict[str, Any]:
    if not path.exists() or path.is_symlink() or not path.is_file():
        return {"schema_version": COMPLETION_CACHE_SCHEMA_VERSION, "profiles": {}}
    try:
        if path.stat().st_size > MAX_COMPLETION_CACHE_BYTES:
            return {"schema_version": COMPLETION_CACHE_SCHEMA_VERSION, "profiles": {}}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"schema_version": COMPLETION_CACHE_SCHEMA_VERSION, "profiles": {}}
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != COMPLETION_CACHE_SCHEMA_VERSION
        or not isinstance(value.get("profiles"), dict)
    ):
        return {"schema_version": COMPLETION_CACHE_SCHEMA_VERSION, "profiles": {}}
    normalized: dict[str, Any] = {
        "schema_version": COMPLETION_CACHE_SCHEMA_VERSION,
        "profiles": {},
    }
    for raw_profile_name, raw_profile in list(value["profiles"].items())[:100]:
        profile_name = _safe_completion_value(raw_profile_name)
        if profile_name is None or not isinstance(raw_profile, dict):
            continue
        profile: dict[str, Any] = {}
        for kind in COMPLETION_CACHE_KINDS:
            entry = raw_profile.get(kind)
            if not isinstance(entry, dict) or not isinstance(entry.get("values"), list):
                continue
            try:
                updated_at = float(entry.get("updated_at"))
            except (TypeError, ValueError):
                continue
            values = [
                candidate
                for item in entry["values"][:1000]
                if (candidate := _safe_completion_value(item)) is not None
            ]
            profile[kind] = {"updated_at": updated_at, "values": values}
        normalized["profiles"][profile_name] = profile
    return normalized


def remember_completion_values(
    profile_name: str,
    kind: str,
    rows: object,
    *,
    fields: tuple[str, ...],
    stamp: float | None = None,
) -> None:
    """Cache public list labels without storing API responses or secrets."""

    if kind not in COMPLETION_CACHE_KINDS:
        raise ValueError(f"unsupported completion cache kind: {kind}")
    safe_profile = _safe_completion_value(profile_name)
    if safe_profile is None:
        return
    candidates = rows if isinstance(rows, list) else []
    values: list[str] = []
    for row in candidates[:500]:
        if not isinstance(row, Mapping):
            continue
        for field in fields:
            candidate = _safe_completion_value(row.get(field))
            if candidate is not None and candidate not in values:
                values.append(candidate)
    path = _completion_cache_path()
    cache = _read_completion_cache(path)
    profiles = cache.setdefault("profiles", {})
    profile = profiles.setdefault(safe_profile, {})
    profile[kind] = {
        "updated_at": time.time() if stamp is None else stamp,
        "values": values,
    }
    encoded = json.dumps(cache, sort_keys=True) + "\n"
    if len(encoded.encode("utf-8")) > MAX_COMPLETION_CACHE_BYTES:
        encoded = (
            json.dumps(
                {
                    "schema_version": COMPLETION_CACHE_SCHEMA_VERSION,
                    "profiles": {safe_profile: {kind: profile[kind]}},
                },
                sort_keys=True,
            )
            + "\n"
        )
    try:
        _atomic_write(path, encoded, mode=0o600)
    except OSError:
        return


def cached_completion_values(
    profile_name: str | None,
    kind: str,
    *,
    now: float | None = None,
) -> tuple[str, ...]:
    if kind not in COMPLETION_CACHE_KINDS:
        return ()
    try:
        current, _ = ProfileStore().load()
    except (OSError, ProfileError, UnicodeError, yaml.YAMLError):
        current = None
    selected = _safe_completion_value(profile_name or current)
    if selected is None:
        return ()
    cache = _read_completion_cache(_completion_cache_path())
    profiles = cache.get("profiles")
    profile = profiles.get(selected) if isinstance(profiles, dict) else None
    entry = profile.get(kind) if isinstance(profile, dict) else None
    if not isinstance(entry, dict) or not isinstance(entry.get("values"), list):
        return ()
    try:
        age = (time.time() if now is None else now) - float(entry.get("updated_at"))
    except (TypeError, ValueError):
        return ()
    if age < 0 or age > COMPLETION_CACHE_TTL_SECONDS:
        return ()
    return tuple(
        candidate
        for value in entry["values"][:1000]
        if (candidate := _safe_completion_value(value)) is not None
    )


def _profile_completer(**_kwargs: Any) -> Iterable[str]:
    try:
        _, profiles = ProfileStore().load()
    except (OSError, ProfileError, UnicodeError, yaml.YAMLError):
        return ()
    return tuple(profiles)


def _workflow_completer(**_kwargs: Any) -> Iterable[str]:
    try:
        installed = WorkflowRegistry().installed()
    except (OSError, RegistryError, UnicodeError, ValueError, yaml.YAMLError):
        return ()
    by_id: dict[str, list[str]] = {}
    for item in installed:
        workflow_id = _safe_completion_value(item.manifest.id)
        version = _safe_completion_value(item.manifest.version)
        if workflow_id is not None and version is not None:
            by_id.setdefault(workflow_id, []).append(version)
    values: list[str] = []
    for workflow_id, versions in sorted(by_id.items()):
        values.append(workflow_id)
        values.extend(f"{workflow_id}@{version}" for version in sorted(set(versions)))
    return values


def _workflow_id_completer(**_kwargs: Any) -> Iterable[str]:
    return tuple(dict.fromkeys(value.partition("@")[0] for value in _workflow_completer()))


def _cached_completer(kind: str):  # type: ignore[no-untyped-def]
    def complete(*, parsed_args: Any = None, **_kwargs: Any) -> Iterable[str]:
        profile_name = getattr(parsed_args, "profile", None) if parsed_args is not None else None
        return cached_completion_values(profile_name, kind)

    return complete


def configure_parser_completers(parser: Any) -> None:
    """Attach local-only completers; callbacks must never contact the Gateway."""

    def visit(current: Any, path: tuple[str, ...]) -> None:
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    visit(child, (*path, name))
                continue
            if action.dest == "profile" or path == ("profile", "use") and action.dest == "name":
                action.completer = _profile_completer
            elif action.dest == "workflow":
                action.completer = _workflow_completer
            elif action.dest == "workflow_id":
                action.completer = _workflow_id_completer
            elif action.dest in {"worker", "worker_id"}:
                action.completer = _cached_completer("workers")
            elif action.dest == "workspace":
                action.completer = _cached_completer("workspaces")
            elif action.dest in {"task_id", "entry_id"}:
                action.completer = _cached_completer("tasks")
            elif action.dest in _DIRECTORY_ARGUMENTS:
                action.completer = DirectoriesCompleter()
            elif action.dest in _FILE_ARGUMENTS:
                action.completer = FilesCompleter()

    visit(parser, ())


def _atomic_write(path: Path, value: str, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _managed_rc_path(path: Path) -> Path:
    if not path.is_symlink():
        return path
    target = path.resolve(strict=False)
    if target.exists() and not target.is_file():
        raise ValueError(f"shell configuration is not a regular file: {path}")
    return target


def _update_managed_block(path: Path, block: str) -> None:
    target = _managed_rc_path(path)
    if target.exists() and not target.is_file():
        raise ValueError(f"shell configuration is not a regular file: {path}")
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    start = existing.find(MANAGED_BLOCK_START)
    end = existing.find(MANAGED_BLOCK_END)
    if (start < 0) != (end < 0) or (start >= 0 and end < start):
        raise ValueError(f"shell configuration has an incomplete VGen block: {path}")
    if start >= 0:
        end += len(MANAGED_BLOCK_END)
        suffix = existing[end:]
        updated = existing[:start] + block + suffix
    else:
        separator = "" if not existing or existing.endswith("\n") else "\n"
        updated = existing + separator + block + "\n"
    if updated != existing:
        mode = target.stat().st_mode & 0o777 if target.exists() else 0o600
        _atomic_write(target, updated, mode=mode)


def _selected_shells(requested: str, *, login_shell: str | None) -> tuple[str, ...]:
    if requested == "all":
        return SUPPORTED_SHELLS
    if requested in SUPPORTED_SHELLS:
        return (requested,)
    if requested != "auto":
        raise ValueError(f"unsupported shell selection: {requested}")
    detected = Path(login_shell or "").name
    if detected not in SUPPORTED_SHELLS:
        raise ValueError("cannot detect bash or zsh from SHELL; pass --shell explicitly")
    return (detected,)


def install_shell_completion(
    requested: str = "auto",
    *,
    home: Path | None = None,
    login_shell: str | None = None,
) -> dict[str, Any]:
    user_home = (home or Path.home()).expanduser().resolve()
    shells = _selected_shells(
        requested,
        login_shell=login_shell if login_shell is not None else os.environ.get("SHELL"),
    )
    completion_dir = user_home / ".local" / "share" / "vgen" / "completions"
    installed: list[dict[str, str]] = []
    for shell in shells:
        script = completion_dir / f"vgen.{shell}"
        _atomic_write(script, shell_completion(shell), mode=0o644)
        rc_file = user_home / (".bashrc" if shell == "bash" else ".zshrc")
        source_path = shlex.quote(str(script))
        shell_setup = (
            "if ! (( $+functions[compdef] )); then\n  autoload -Uz compinit\n  compinit\nfi\n"
            if shell == "zsh"
            else ""
        )
        block = (
            f"{MANAGED_BLOCK_START}\n"
            f"{shell_setup}"
            f"if [ -r {source_path} ]; then\n"
            f"  . {source_path}\n"
            "fi\n"
            f"{MANAGED_BLOCK_END}"
        )
        _update_managed_block(rc_file, block)
        installed.append({"shell": shell, "script": str(script), "rc_file": str(rc_file)})
    return {"installed": True, "shells": installed, "restart_required": True}


def completion_command(args: Any) -> None:
    if args.completion_action in SUPPORTED_SHELLS:
        print(shell_completion(args.completion_action), end="")
        return
    if args.completion_action == "install":
        print(
            json.dumps(
                install_shell_completion(args.shell),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return
    raise ValueError("unsupported completion action")
