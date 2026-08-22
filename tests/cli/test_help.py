from __future__ import annotations

import argparse

from vgen.cli.main import build_parser


def _subparser(parser: argparse.ArgumentParser, *path: str) -> argparse.ArgumentParser:
    current = parser
    for name in path:
        action = next(
            item
            for item in current._actions
            if isinstance(item, argparse._SubParsersAction)
        )
        current = action.choices[name]
    return current


def test_every_visible_cli_command_and_argument_has_useful_help() -> None:
    parser = build_parser()
    missing: list[str] = []
    generic: list[str] = []

    def visit(current: argparse.ArgumentParser, path: tuple[str, ...]) -> None:
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                if len(action._choices_actions) != len(action.choices):
                    missing.append("/".join((*path, "<commands>")))
                for choice in action._choices_actions:
                    if not choice.help:
                        missing.append("/".join((*path, choice.dest)))
                for name, child in action.choices.items():
                    visit(child, (*path, name))
            elif action.dest != "help" and action.help != argparse.SUPPRESS:
                location = "/".join((*path, action.dest))
                if not action.help:
                    missing.append(location)
                if str(action.help).startswith("设置 "):
                    generic.append(location)

    visit(parser, ())

    assert missing == []
    assert generic == []


def test_cli_help_explains_common_and_advanced_flows_in_chinese() -> None:
    parser = build_parser()
    root_help = parser.format_help()
    join_help = _subparser(parser, "join").format_help()
    invite_help = _subparser(parser, "workspace", "invite").format_help()
    worker_help = _subparser(parser, "worker", "serve").format_help()
    submit_help = _subparser(parser, "task", "submit").format_help()

    assert "通过 Gateway 安全共享 GPU Worker" in root_help
    assert "vgen task submit" in root_help
    assert "管理 Workspace、资源池、成员准入、密钥和审计记录" in root_help
    assert "direct_invite 领取即生效" in invite_help
    assert "避免 secret 进入命令历史" in join_help
    assert "本机 ComfyUI API 地址" in worker_help
    assert "首帧图片路径；不指定图片时执行文生视频" in submit_help
    assert "尾帧图片路径；与 --image 同时指定时生成首尾帧视频" in submit_help
    assert "格式为 key=value" in submit_help
