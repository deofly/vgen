from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from vgen.cli.completion import (
    MANAGED_BLOCK_END,
    MANAGED_BLOCK_START,
    install_shell_completion,
    shell_completion,
)
from vgen.cli.main import build_parser, dispatch


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
