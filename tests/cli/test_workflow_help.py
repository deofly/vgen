from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from vgen.cli import main as cli
from vgen.cli.video_inputs import H3_FACE_DIGEST
from vgen.cli.workflow_catalog import workflow_index, write_catalog_cache
from vgen.cli.workflow_help import FACE_PROMPT, face_commands, parameter_help, workflow_usage
from vgen.market.models import WorkflowManifest
from vgen.market.registry import WorkflowRegistry

PACKAGE = Path(__file__).parents[2] / "workflows/vgen/minimax-h3-face-reference/1.0.0"


def test_face_example_commands_parse_and_pass_actual_parameter_validation():
    manifest = WorkflowManifest.load(PACKAGE / "manifest.yaml")
    for command in face_commands():
        args = cli.build_parser().parse_args(shlex.split(shlex.join(command))[1:])
        parameters = cli._effective_parameters(manifest, args)
        assert parameters["image"] == "face.png"
        assert parameters["video"] == "original.mp4"
        assert parameters["width"] == 480 and parameters["height"] == 832
        if args.task_action == "submit":
            assert args.prompt == FACE_PROMPT
            assert args.video_fps_mode == "auto"
        horizontal = cli.build_parser().parse_args(
            command[1:] + ["-p", "width=832", "-p", "height=480"]
        )
        assert cli._effective_parameters(manifest, horizontal)["width"] == 832


def test_workflow_help_reads_cached_code_offline_without_installing(tmp_path, monkeypatch, capsys):
    registry = WorkflowRegistry(tmp_path / "registry")
    registry.install(PACKAGE, allow_unsigned=True)
    write_catalog_cache(
        registry.root,
        workflow_index(),
        [
            {
                "id": "vgen/minimax-h3-face-reference",
                "version": "1.0.0",
                "code": "h3-face",
                "source": "https://market.example/face.zip",
                "digest": "sha256:" + H3_FACE_DIGEST,
            }
        ],
    )
    monkeypatch.setattr(cli, "WorkflowRegistry", lambda: registry)

    def no_network(*args, **kwargs):
        pytest.fail("installed workflow help must work offline")

    monkeypatch.setattr(WorkflowRegistry, "_download", staticmethod(no_network))
    cli.dispatch(cli.build_parser().parse_args(["workflow", "help", "h3-face"]))
    output = capsys.readouterr().out
    assert "示例提示词" in output and FACE_PROMPT in output
    assert "steps（-p steps=值）：可选；integer；默认 20；>= 20；<= 30" in output
    assert "width=832, height=480" in output
    assert "--video-fps-mode strict" in output
    assert "-p fps=..." in output and "不是 -p 工作流参数" in output
    assert len(registry.installed()) == 1
    cli.dispatch(cli.build_parser().parse_args(["workflow", "show", "h3-face", "--format", "json"]))
    assert set(json.loads(capsys.readouterr().out)) == {"manifest", "digest", "signed"}


def test_parameter_help_uses_schema_constraints_and_strips_terminal_controls():
    manifest = WorkflowManifest.load(PACKAGE / "manifest.yaml")
    manifest.parameters["properties"]["steps"].update(
        minimum=22, maximum=28, default=24, description="说明\x1b[31m\n下一行"
    )
    text = parameter_help(manifest, H3_FACE_DIGEST)
    assert "默认 24；>= 22；<= 28" in text
    assert "\x1b" not in text and "说明 [31m 下一行" in text


def test_other_workflows_use_their_own_prompt_examples_and_do_not_get_face_options():
    manifest = WorkflowManifest.load(PACKAGE / "manifest.yaml")
    manifest.id = "example/other"
    prompt = "A person's portrait; $(this_is_only_text)"
    manifest.parameters["properties"]["prompt"]["examples"] = [prompt]
    text = workflow_usage(manifest, "a" * 64, "other@1.0.0")
    submit = next(
        line.strip() for line in text.splitlines() if line.strip().startswith("vgen task submit ")
    )
    args = cli.build_parser().parse_args(shlex.split(submit)[1:])
    assert args.prompt == prompt
    assert "--video-fps-mode" not in text and FACE_PROMPT not in text


def test_general_help_has_examples_without_loading_workflow_or_profile(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("--help must not inspect workflows or authenticate")

    monkeypatch.setattr(cli, "WorkflowRegistry", forbidden)
    monkeypatch.setattr(cli, "_client", forbidden)
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["task", "submit", "--help"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    assert "vgen workflow help h3-face" in output and FACE_PROMPT in output
