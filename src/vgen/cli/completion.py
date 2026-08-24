from __future__ import annotations

import json
import os
import shlex
import tempfile
from pathlib import Path
from typing import Any

import argcomplete

SUPPORTED_SHELLS = ("bash", "zsh")
MANAGED_BLOCK_START = "# >>> vgen shell completion >>>"
MANAGED_BLOCK_END = "# <<< vgen shell completion <<<"


def shell_completion(shell: str) -> str:
    if shell not in SUPPORTED_SHELLS:
        raise ValueError(f"unsupported shell: {shell}")
    return argcomplete.shellcode(["vgen"], shell=shell).rstrip() + "\n"


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
