"""Readable, copyable usage derived from workflow parameter schemas."""

from __future__ import annotations

import json
import shlex
from typing import Any

from vgen.market.models import WorkflowManifest

from .video_inputs import H3_FACE_RELEASE_DIGESTS

FACE_PROMPT = (
    "Use <Picture 1> only for facial identity. Replace the single visible face in "
    "<Video 1>, retaining the original clothing, hairstyle, lighting, background, "
    "camera motion, body movement, dialogue and timing. Keep the same facial identity "
    "throughout. Do not add people, cuts, captions or new dialogue."
)
FACE_PARAMETER_NOTES = {
    "prompt": "照片提供脸部身份，原视频提供动作和场景；保留 <Picture 1> 与 <Video 1> 引用。",
    "image": "本人或已获授权的清晰单人脸照片。",
    "video": "带音轨的单人原视频；选定起点后至少剩余约 5.17 秒。",
    "seed": "为兼容 1.x 命令而保留；2.x 是确定性逐帧处理，不使用随机数。",
    "steps": "采样步数；先使用默认值，增加步数会增加耗时。",
    "width": "输出宽度；必须与 height 满足下方组合约束。",
    "height": "输出高度；必须与 width 满足下方组合约束。",
    "start_time": "从原视频第几秒开始；自动模式在本地选段一次，画面和音轨使用同一起点。",
    "ref_image_size": "match 控制参考计算量；max 提高参考尺寸，可能增加耗时和显存占用。",
    "strength": "人脸替换强度；默认 1.0。",
    "identity_shape": "来源脸型比例保留程度；侧脸不稳时可降低。",
    "feather": "换脸区域边缘羽化宽度。",
}
INPUT_OPTIONS = {"image": "--image", "last_image": "--last-image", "video": "--video"}
INPUT_EXAMPLES = {"image": "./face.png", "last_image": "./last.png", "video": "./original.mp4"}


def _text(value: Any) -> str:
    return " ".join("".join(c if c.isprintable() else " " for c in str(value)).split())


def _json(value: Any) -> str:
    return _text(json.dumps(value, ensure_ascii=False))


def is_face_help(manifest: WorkflowManifest, digest: str) -> bool:
    return H3_FACE_RELEASE_DIGESTS.get((manifest.id, manifest.version)) == digest


def parameter_help(manifest: WorkflowManifest, digest: str) -> str:
    schema = manifest.parameters
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    face = is_face_help(manifest, digest)
    lines = ["参数（工作流参数使用 -p 名称=值；素材使用专用选项）："]
    for name, raw in properties.items():
        definition = raw if isinstance(raw, dict) else {}
        usage = (
            "位置参数 <prompt>" if name == "prompt" else INPUT_OPTIONS.get(name, f"-p {name}=值")
        )
        facts = ["必填" if name in required else "可选", _text(definition.get("type", "任意类型"))]
        if "default" in definition:
            facts.append(f"默认 {_json(definition['default'])}")
        for key, label in (
            ("enum", "可选值"),
            ("const", "固定值"),
            ("minimum", ">="),
            ("maximum", "<="),
            ("exclusiveMinimum", ">"),
            ("exclusiveMaximum", "<"),
            ("multipleOf", "必须为其倍数"),
            ("minLength", "最少字符"),
            ("maxLength", "最多字符"),
            ("pattern", "匹配规则"),
        ):
            if key in definition:
                facts.append(f"{label} {_json(definition[key])}")
        if raw is False:
            facts.append("此参数禁止设置")
        lines.append(f"  {_text(name)}（{_text(usage)}）：{'；'.join(facts)}")
        description = definition.get("description") or (
            FACE_PARAMETER_NOTES.get(name) if face else None
        )
        if description:
            lines.append(f"    {_text(description)}")
    for group in ("oneOf", "anyOf"):
        alternatives = schema.get(group)
        if not isinstance(alternatives, list):
            continue
        combinations = []
        for alternative in alternatives:
            definitions = alternative.get("properties", {}) if isinstance(alternative, dict) else {}
            constants = [
                f"{_text(name)}={_json(rule['const'])}"
                for name, rule in definitions.items()
                if isinstance(rule, dict) and "const" in rule
            ]
            if constants:
                combinations.append(", ".join(constants))
        lines.append("参数组合约束：" + (" / ".join(combinations) or "请查看完整 JSON 清单。"))
    lines.append("完整 JSON Schema 以 workflow show <代号> --format json 为准。")
    return "\n".join(lines)


def face_commands(reference: str = "h3-face@2.0.1") -> list[list[str]]:
    shared = ["--workflow", reference, "--image", "./face.png", "--video", "./original.mp4"]
    return [
        ["vgen", "task", "preflight", *shared],
        [
            "vgen",
            "task",
            "submit",
            FACE_PROMPT,
            *shared,
            "--video-fps-mode",
            "auto",
            "-p",
            "seed=1234",
            "--wait",
            "--output-dir",
            "./h3-face-output",
        ],
    ]


def workflow_usage(manifest: WorkflowManifest, digest: str, reference: str) -> str:
    face = is_face_help(manifest, digest)
    if face:
        precise_swap = manifest.version.startswith("2.")
        lines = [
            "使用前：",
            (
                "  这是逐帧单人换脸：保留原视频画面和音轨，只修改检测到的人脸区域。"
                if precise_swap
                else "  这是预览版参考重生成，并非逐帧精确换脸。"
            ),
            "  需要支持视频输入的 CLI/Gateway/Worker，Executor >=1.3.0、ComfyUI >=0.33.0。",
            (
                "  先安装工作流、MediaPipe 模型和受审查 Node Pack；本机需 FFmpeg。"
                if precise_swap
                else "  先在 Worker 安装工作流及 Ref2VA 模型；本机需 FFmpeg。"
            ),
            "  输出固定为 124 帧、24 fps、约 5.17 秒；分辨率跟随本地适配后的视频。",
            "CLI 选项（不是 -p 工作流参数）：",
            "  --video-fps-mode auto：默认，检测原帧率并自动选段/转换为 24 fps；原文件不变。",
            "  --video-fps-mode strict：不转码，要求输入片段恒定 24 fps。",
            "  --wait：等待并下载结果；--output-dir：结果保存目录。",
            "  不支持 -p fps=... 或 -p duration=...；auto 不改变输出帧率。",
            "示例提示词（可修改描述，请保留图片和视频引用）：",
            f"  {FACE_PROMPT}",
            "命令示例（Bash / Zsh；把素材路径替换为自己的文件，先预检再提交）：",
            *(f"  {shlex.join(command)}" for command in face_commands(reference)),
            (
                "可调替换强度：-p strength=0.85；侧脸不稳可用 -p identity_shape=0.15。"
                if precise_swap
                else "横屏：在提交命令后追加 -p width=832 -p height=480。"
            ),
            "更多 CLI 选项：vgen task submit --help",
        ]
        return "\n".join(lines)
    properties = manifest.parameters.get("properties", {})
    if "prompt" not in properties:
        return "此工作流未声明标准 prompt 参数；请根据完整清单和作者说明调用。"
    definition = properties["prompt"]
    examples = definition.get("examples", []) if isinstance(definition, dict) else []
    prompt = next(
        (item for item in examples if isinstance(item, str) and item), "<描述你想生成的画面>"
    )
    options = ["--workflow", reference]
    for name in manifest.parameters.get("required", []):
        rule = properties.get(name, {})
        if name == "prompt" or isinstance(rule, dict) and "default" in rule:
            continue
        if name in INPUT_OPTIONS:
            options.extend([INPUT_OPTIONS[name], INPUT_EXAMPLES[name]])
        else:
            options.extend(["-p", f"{name}=<{name}>"])
    commands = [
        ["vgen", "task", "preflight", prompt, *options],
        ["vgen", "task", "submit", prompt, *options, "--wait", "--output-dir", "./vgen-output"],
    ]
    return "\n".join(
        [
            "命令模板（Bash / Zsh；替换尖括号占位符和素材路径，先预检再提交）：",
            *("  " + _text(shlex.join(command)) for command in commands),
            "更多 CLI 选项：vgen task submit --help",
        ]
    )


def task_help_examples() -> str:
    return "\n".join(
        [
            "快速示例（Bash / Zsh）：",
            "  vgen task submit '一只猫在草地上奔跑' --workflow h3 --wait",
            "  " + shlex.join(face_commands()[1]),
            "  2.x 保留原视频构图；-p seed=1234 仅兼容旧命令，不影响结果。",
            "  h3-face 2.x 需支持视频输入的运行环境、受审查 Node Pack 及本机 FFmpeg。",
            "  auto 为默认模式，自动处理原视频帧率；输出仍为 24 fps、约 5.17 秒。",
            "查看指定工作流的提示词、必填项、默认值和取值范围：",
            "  vgen workflow help h3-face",
            "  vgen workflow help h3",
            "其他工作流的参数由清单决定，不要直接套用 h3-face 的参数。",
        ]
    )
