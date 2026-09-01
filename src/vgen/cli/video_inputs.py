"""Local media adaptation for reviewed h3-face workflow releases."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

H3_FACE_RELEASE = ("vgen/minimax-h3-face-reference", "2.0.0")
# Populated with the exact reviewed archive digest for every compatible release.
# The legacy release remains supported for installed/offline callers.
H3_FACE_RELEASE_DIGESTS = {
    ("vgen/minimax-h3-face-reference", "1.0.0"): (
        "a2d5fc8d4acb9f667ea625d3037ae13142f9f76a5c5d6576df80cd1158cd9463"
    ),
    ("vgen/minimax-h3-face-reference", "1.0.1"): (
        "b2275088cc2af6afa7a4efc652bb6dd1354b44643ad1593805bbb34814e07f46"
    ),
    H3_FACE_RELEASE: "d212cdbdc83472e0172aef4715438427e44934f021da5adabfeeb5a07e4f0138",
}
H3_FACE_DIGEST = H3_FACE_RELEASE_DIGESTS[H3_FACE_RELEASE]
H3_FPS = 24
H3_FRAMES = 124
H3_DURATION = Fraction(H3_FRAMES, H3_FPS)


def _binary(name: str) -> str:
    binary = shutil.which(name)
    if binary is None:
        raise ValueError(f"H3 视频自动检测需要 {name}；请先安装 FFmpeg（包含 ffprobe）。")
    return binary


def _run(command: list[str], *, timeout: int) -> bytes:
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("本地视频检测或转换失败/超时；未提交生成任务。") from exc
    if result.returncode:
        # Decoder output may contain private paths, metadata and terminal controls.
        raise ValueError("无法读取或转换视频；请检查文件是否损坏、编码是否受 FFmpeg 支持。")
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("视频检测信息超过安全大小限制。")
    return result.stdout


def _probe(path: Path, arguments: list[str]) -> dict[str, Any]:
    raw = _run(
        [
            _binary("ffprobe"),
            "-v",
            "error",
            "-protocol_whitelist",
            "file,pipe",
            *arguments,
            "-of",
            "json",
            str(path),
        ],
        timeout=30,
    )
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError) as exc:
        raise ValueError("无法解析视频检测信息。") from exc


def _fraction(value: Any) -> Fraction | None:
    try:
        return Fraction(str(value))
    except (ValueError, ZeroDivisionError):
        return None


@dataclass(frozen=True)
class VideoInfo:
    fps: Fraction
    duration: Fraction
    variable_frame_rate: bool
    constant_24fps: bool


def inspect_video(path: Path, start_time: float = 0) -> VideoInfo:
    if not path.is_file():
        raise ValueError("参考视频文件不存在。")
    metadata = _probe(
        path,
        [
            "-show_entries",
            "stream=codec_type,width,height,avg_frame_rate,r_frame_rate,time_base,duration,start_time:format=duration",
        ],
    )
    streams = metadata.get("streams", [])
    video = next((row for row in streams if row.get("codec_type") == "video"), None)
    if video is None or not any(row.get("codec_type") == "audio" for row in streams):
        raise ValueError("此 H3 人脸参考包需要视频画面和原音轨；请选择带音轨的视频。")
    fps = _fraction(video.get("avg_frame_rate")) or _fraction(video.get("r_frame_rate"))
    duration = _fraction(video.get("duration")) or _fraction(
        metadata.get("format", {}).get("duration")
    )
    start = _fraction(start_time)
    if fps is None or not 0 < fps <= 240 or duration is None or duration <= 0:
        raise ValueError("无法确定有效的视频帧率/时长，或帧率超过 240 fps。")
    if start is None or start < 0 or start + H3_DURATION > duration + Fraction(1, 1000):
        raise ValueError("从 start_time 起的视频不足 124/24 秒（约 5.17 秒）；请选择更早的起点。")
    origin = _fraction(video.get("start_time")) or Fraction(0)
    begin, end = start + origin, start + origin + H3_DURATION
    frames = _probe(
        path,
        [
            "-select_streams",
            "v:0",
            "-read_intervals",
            f"{float(begin):.9f}%{float(end):.9f}",
            "-show_entries",
            "frame=best_effort_timestamp_time",
        ],
    ).get("frames", [])
    timestamps = [
        stamp
        for row in frames
        if (stamp := _fraction(row.get("best_effort_timestamp_time"))) is not None
        and begin <= stamp < end
    ]
    if len(timestamps) < 2:
        raise ValueError("无法检测所选片段的帧时间戳；请先将视频转存为普通 MP4。")
    intervals = [right - left for left, right in zip(timestamps, timestamps[1:], strict=False)]
    if any(value <= 0 for value in intervals):
        raise ValueError("视频帧时间戳不连续；请先修复或转存视频。")
    tolerance = max(Fraction(1, 10000), (_fraction(video.get("time_base")) or Fraction(0)) * 2)
    variable = max(intervals) - min(intervals) > tolerance
    constant_24 = (
        not variable
        and abs(fps - H3_FPS) < Fraction(1, 10000)
        and all(abs(value - Fraction(1, H3_FPS)) <= tolerance for value in intervals)
        and timestamps[0] <= begin + Fraction(1, H3_FPS) + tolerance
        and timestamps[-1] >= end - Fraction(1, H3_FPS) - tolerance
    )
    return VideoInfo(fps, duration, variable, constant_24)


@dataclass(frozen=True)
class PreparedVideo:
    path: Path
    start_time: float
    info: VideoInfo
    mode: str

    def report(self) -> dict[str, Any]:
        return {
            "source_fps": float(self.info.fps),
            "source_fps_ratio": str(self.info.fps),
            "variable_frame_rate": self.info.variable_frame_rate,
            "model_fps": H3_FPS,
            "clip_duration_seconds": float(H3_DURATION),
            "mode": self.mode,
        }


@contextmanager
def prepare_reference_video(
    workflow_id: str,
    version: str,
    digest: str,
    value: str | None,
    *,
    start_time: float = 0,
    mode: str | None = None,
    dry_run: bool = False,
) -> Iterator[PreparedVideo | None]:
    release = (workflow_id, version)
    expected_digest = H3_FACE_RELEASE_DIGESTS.get(release)
    if expected_digest is None:
        if mode is not None:
            raise ValueError("--video-fps-mode 当前仅适用于已审查的 h3-face 版本。")
        yield None
        return
    if digest != expected_digest:
        raise ValueError("H3 人脸参考包摘要与已审查版本不符，不能自动适配视频。")
    if not value:
        raise ValueError("此工作流需要 --video。")
    mode = mode or "auto"
    if mode not in {"auto", "strict"}:
        raise ValueError("video fps mode must be auto or strict")
    path = Path(value).expanduser().resolve()
    info = inspect_video(path, start_time)
    if mode == "strict" and not info.constant_24fps:
        raise ValueError(
            f"检测到 {float(info.fps):g} fps"
            f"{'（可变帧率）' if info.variable_frame_rate else ''}；"
            "严格模式要求恒定 24 fps，请使用 --video-fps-mode auto。"
        )
    if mode == "auto":
        ffmpeg = _binary("ffmpeg")
    print(
        f"参考视频：平均 {float(info.fps):g} fps"
        f"{'，可变帧率' if info.variable_frame_rate else ''}；"
        f"{'将自动选段并转换为 24 fps，原文件不变' if mode == 'auto' else '恒定 24 fps 检查通过'}。",
        file=sys.stderr,
    )
    if dry_run or mode == "strict":
        yield PreparedVideo(path, start_time, info, mode)
        return
    with tempfile.TemporaryDirectory(prefix="vgen-video-input-") as temporary:
        output = Path(temporary) / "reference-video.mp4"
        _run(
            [
                ffmpeg,
                "-nostdin",
                "-hide_banner",
                "-v",
                "error",
                "-n",
                "-protocol_whitelist",
                "file,pipe",
                "-ss",
                str(start_time),
                "-i",
                str(path),
                "-t",
                f"{float(H3_DURATION):.9f}",
                "-map",
                "0:v:0",
                "-map",
                "0:a:0",
                "-map_metadata",
                "-1",
                "-map_chapters",
                "-1",
                "-vf",
                "fps=24,scale=1280:1280:force_original_aspect_ratio=decrease:force_divisible_by=2,setsar=1",
                "-c:v",
                "libx264",
                "-crf",
                "18",
                "-pix_fmt",
                "yuv420p",
                "-fps_mode",
                "cfr",
                "-c:a",
                "aac",
                "-b:a",
                "192k",
                "-movflags",
                "+faststart",
                str(output),
            ],
            timeout=180,
        )
        checked = inspect_video(output)
        if not checked.constant_24fps:
            raise ValueError("转换后的参考视频未通过恒定 24 fps 校验；未提交任务。")
        yield PreparedVideo(output, 0, info, mode)
