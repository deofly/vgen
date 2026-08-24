from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from argcomplete.completers import DirectoriesCompleter, FilesCompleter

from vgen.cli import completion
from vgen.cli.completion import (
    COMPLETION_CACHE_TTL_SECONDS,
    MANAGED_BLOCK_END,
    MANAGED_BLOCK_START,
    cached_completion_values,
    install_shell_completion,
    remember_completion_values,
    shell_completion,
)
from vgen.cli.main import build_parser, dispatch
from vgen.cli.profile import GatewayProfile


def _subparser_action(*path: str, dest: str):  # type: ignore[no-untyped-def]
    import argparse

    current = build_parser()
    for name in path:
        subparsers = next(
            action for action in current._actions if isinstance(action, argparse._SubParsersAction)
        )
        current = subparsers.choices[name]
    return next(action for action in current._actions if action.dest == dest)


@pytest.mark.parametrize("shell", ("bash", "zsh"))
def test_completion_command_prints_argparse_registration(
    shell: str, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = build_parser().parse_args(["completion", shell])

    dispatch(arguments)

    output = capsys.readouterr().out
    assert "_python_argcomplete" in output
    assert " vgen" in output
    assert f'_ARGCOMPLETE_SHELL="{shell}"' in output
    assert output == shell_completion(shell)


@pytest.mark.parametrize(
    ("line", "expected"),
    (
        ("vgen wor", {"workspace", "worker", "workflow"}),
        ("vgen task list --f", {"--format "}),
    ),
)
def test_argcomplete_protocol_reads_the_real_parser(line: str, expected: set[str]) -> None:
    root = Path(__file__).resolve().parents[2]
    environment = os.environ | {
        "PYTHONPATH": str(root / "src"),
        "COMP_LINE": line,
        "COMP_POINT": str(len(line)),
        "COMP_TYPE": "9",
        "_ARGCOMPLETE": "1",
        "_ARGCOMPLETE_IFS": "\v",
        "_ARGCOMPLETE_SHELL": "bash",
    }

    result = subprocess.run(
        ["/bin/bash", "-c", f"{shlex.quote(sys.executable)} -m vgen 8>&1"],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    assert set(result.stdout.split("\v")) == expected


def test_profile_and_workflow_values_come_only_from_local_stores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profiles = {
        "home": GatewayProfile("home", "https://gateway.example"),
        "studio": GatewayProfile("studio", "https://studio.example"),
    }
    installed = [
        SimpleNamespace(manifest=SimpleNamespace(id="vgen/demo", version="1.0.0")),
        SimpleNamespace(manifest=SimpleNamespace(id="vgen/demo", version="2.0.0")),
        SimpleNamespace(manifest=SimpleNamespace(id="custom/portrait", version="1.1.0")),
    ]
    monkeypatch.setattr(
        completion,
        "ProfileStore",
        lambda: SimpleNamespace(load=lambda: ("home", profiles)),
    )
    monkeypatch.setattr(
        completion,
        "WorkflowRegistry",
        lambda: SimpleNamespace(installed=lambda: installed),
    )

    profile_action = _subparser_action("task", "list", dest="profile")
    workflow_action = _subparser_action("task", "submit", dest="workflow")
    workflow_id_action = _subparser_action("workflow", "remove", dest="workflow_id")

    assert set(profile_action.completer()) == {"home", "studio"}
    assert set(workflow_action.completer()) == {
        "custom/portrait",
        "custom/portrait@1.1.0",
        "vgen/demo",
        "vgen/demo@1.0.0",
        "vgen/demo@2.0.0",
    }
    assert set(workflow_id_action.completer()) == {"custom/portrait", "vgen/demo"}


def test_file_and_directory_arguments_use_native_shell_completion() -> None:
    image = _subparser_action("task", "submit", dest="image")
    output_dir = _subparser_action("task", "submit", dest="output_dir")
    credentials = _subparser_action("worker", "serve", dest="credentials_file")

    assert isinstance(image.completer, FilesCompleter)
    assert isinstance(credentials.completer, FilesCompleter)
    assert isinstance(output_dir.completer, DirectoriesCompleter)


def test_remote_ids_use_profile_scoped_short_lived_cache_without_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_path = tmp_path / "completion-values.json"
    monkeypatch.setattr(completion, "_completion_cache_path", lambda: cache_path)
    monkeypatch.setattr(
        completion,
        "ProfileStore",
        lambda: SimpleNamespace(load=lambda: ("home", {})),
    )
    remember_completion_values(
        "home",
        "workers",
        [
            {
                "id": "wrk_example",
                "name": "Studio GPU",
                "invite_uri": "vgen://invite/SECRET",
                "private_key": "SECRET_KEY",
            }
        ],
        fields=("id", "name"),
        stamp=1_000,
    )
    remember_completion_values(
        "other",
        "workers",
        [{"id": "wrk_other", "name": "Other GPU"}],
        fields=("id", "name"),
        stamp=1_000,
    )

    assert cached_completion_values("home", "workers", now=1_001) == (
        "wrk_example",
        "Studio GPU",
    )
    assert cached_completion_values(None, "workers", now=1_001) == (
        "wrk_example",
        "Studio GPU",
    )
    assert cached_completion_values("other", "workers", now=1_001) == (
        "wrk_other",
        "Other GPU",
    )
    assert (
        cached_completion_values(
            "home",
            "workers",
            now=1_000 + COMPLETION_CACHE_TTL_SECONDS + 1,
        )
        == ()
    )
    serialized = cache_path.read_text(encoding="utf-8")
    assert "SECRET" not in serialized
    assert cache_path.stat().st_mode & 0o777 == 0o600


def test_worker_workspace_and_task_actions_read_only_the_completion_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        completion,
        "_completion_cache_path",
        lambda: tmp_path / "completion-values.json",
    )
    monkeypatch.setattr(
        completion,
        "ProfileStore",
        lambda: SimpleNamespace(load=lambda: ("home", {})),
    )
    for kind, field, value in (
        ("workers", "id", "wrk_cached"),
        ("workspaces", "id", "wsp_cached"),
        ("tasks", "id", "tsk_cached"),
    ):
        remember_completion_values("home", kind, [{field: value}], fields=(field,))

    worker = _subparser_action("worker", "upgrade", dest="worker")
    workspace = _subparser_action("task", "list", dest="workspace")
    task = _subparser_action("task", "show", dest="task_id")
    parsed = SimpleNamespace(profile="home")

    assert tuple(worker.completer(parsed_args=parsed)) == ("wrk_cached",)
    assert tuple(workspace.completer(parsed_args=parsed)) == ("wsp_cached",)
    assert tuple(task.completer(parsed_args=parsed)) == ("tsk_cached",)


def test_completion_install_is_idempotent_and_preserves_existing_rc(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home with spaces"
    home.mkdir()
    zshrc = home / ".zshrc"
    zshrc.write_text("export BEFORE_VGEN=1\n", encoding="utf-8")

    first = install_shell_completion("zsh", home=home)
    second = install_shell_completion("zsh", home=home)

    assert first == second
    script = home / ".local/share/vgen/completions/vgen.zsh"
    assert script.read_text(encoding="utf-8") == shell_completion("zsh")
    contents = zshrc.read_text(encoding="utf-8")
    assert contents.startswith("export BEFORE_VGEN=1\n")
    assert contents.count(MANAGED_BLOCK_START) == 1
    assert contents.count(MANAGED_BLOCK_END) == 1
    assert "autoload -Uz compinit" in contents
    assert str(script) in contents
    assert first["shells"][0]["rc_file"] == str(zshrc)


def test_completion_install_all_writes_bash_and_zsh_activation(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    result = install_shell_completion("all", home=home)

    assert [item["shell"] for item in result["shells"]] == ["bash", "zsh"]
    bashrc = home / ".bashrc"
    zshrc = home / ".zshrc"
    assert "vgen.bash" in bashrc.read_text(encoding="utf-8")
    assert "vgen.zsh" in zshrc.read_text(encoding="utf-8")
    subprocess.run(["/bin/bash", "-n", str(bashrc)], check=True)
    subprocess.run(["/bin/zsh", "-n", str(zshrc)], check=True)


def test_completion_install_auto_uses_login_shell(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    result = install_shell_completion("auto", home=home, login_shell="/bin/bash")

    assert [item["shell"] for item in result["shells"]] == ["bash"]
    assert (home / ".bashrc").is_file()
    assert not (home / ".zshrc").exists()


def test_completion_install_rejects_incomplete_managed_block(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".zshrc").write_text(MANAGED_BLOCK_START + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="incomplete VGen block"):
        install_shell_completion("zsh", home=home)


def test_completion_install_cli_returns_machine_readable_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SHELL", "/bin/zsh")

    dispatch(build_parser().parse_args(["completion", "install"]))

    receipt = json.loads(capsys.readouterr().out)
    assert receipt["installed"] is True
    assert receipt["shells"][0]["shell"] == "zsh"
    assert receipt["restart_required"] is True
