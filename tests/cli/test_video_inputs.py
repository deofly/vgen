from __future__ import annotations

import json
import shutil
import struct
import subprocess
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest

from vgen.cli import main as cli
from vgen.cli import video_inputs as video
from vgen.market.builder import build_comfy_graph
from vgen.market.models import WorkflowManifest

PACKAGE = Path(__file__).parents[2] / "workflows/vgen/minimax-h3-face-reference/2.0.1"
HAS_FFMPEG = shutil.which("ffmpeg") and shutil.which("ffprobe")
media_test = pytest.mark.skipif(not HAS_FFMPEG, reason="real FFmpeg media test")


def make_clip(tmp_path: Path, fps="30", *, vfr=False, audio=True, duration=7) -> Path:
    path = tmp_path / f"private-person-{fps.replace('/', '-')}-{vfr}-{audio}.mp4"
    command = [
        "ffmpeg",
        "-nostdin",
        "-v",
        "error",
        "-n",
        "-f",
        "lavfi",
        "-i",
        f"testsrc2=size=96x64:rate={fps}:duration={duration}",
    ]
    if audio:
        command += ["-f", "lavfi", "-i", f"sine=frequency=440:duration={duration}"]
    if vfr:
        command += ["-vf", "select='if(lt(t,3),not(mod(n,2)),not(mod(n,3)))'", "-fps_mode", "vfr"]
    command += ["-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p"]
    if audio:
        command += ["-c:a", "aac"]
    subprocess.run([*command, str(path)], capture_output=True, check=True, timeout=30)
    return path


def prepare(path, **kwargs):
    return video.prepare_reference_video(
        *video.H3_FACE_RELEASE, video.H3_FACE_DIGEST, str(path), **kwargs
    )


@media_test
@pytest.mark.parametrize("fps", ["24000/1001", "24", "25", "30000/1001", "30", "60"])
def test_auto_preserves_duration_audio_and_original_for_real_frame_rates(tmp_path, fps):
    original = make_clip(tmp_path, fps)
    before = original.read_bytes()
    with prepare(original, start_time=1) as result:
        assert result.start_time == 0
        assert result.info.fps == Fraction(fps)
        assert video.inspect_video(result.path).constant_24fps
        details = video._probe(result.path, ["-count_frames", "-show_streams"])
        picture = next(row for row in details["streams"] if row["codec_type"] == "video")
        sound = next(row for row in details["streams"] if row["codec_type"] == "audio")
        assert int(picture["nb_read_frames"]) == 124
        assert abs(float(picture["duration"]) - 124 / 24) < 0.002
        assert abs(float(sound["duration"]) - 124 / 24) < 0.03
        assert result.path != original
        processed = result.path
        assert "private-person" not in json.dumps(result.report())
    assert not processed.exists()
    assert original.read_bytes() == before


@media_test
def test_variable_frame_rate_is_detected_and_normalized(tmp_path):
    source = make_clip(tmp_path, "60", vfr=True)
    with prepare(source) as result:
        assert result.info.variable_frame_rate
        assert video.inspect_video(result.path).constant_24fps
    with pytest.raises(ValueError, match="严格模式"):
        with prepare(source, mode="strict"):
            pass


@media_test
def test_video_and_audio_seek_to_the_same_source_time(tmp_path):
    source = tmp_path / "timed-colors-and-tones.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-n",
            "-f",
            "lavfi",
            "-i",
            "color=c=blue:s=96x64:r=25:d=7,drawbox=color=red:t=fill:enable='lt(t,1)'",
            "-f",
            "lavfi",
            "-i",
            r"aevalsrc=0.3*sin(2*PI*(440+440*gte(t\,1))*t):s=48000:d=7",
            "-c:v",
            "libx264",
            "-c:a",
            "aac",
            str(source),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    with prepare(source, start_time=1.2) as result:
        rgb = subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-i",
                str(result.path),
                "-frames:v",
                "1",
                "-f",
                "rawvideo",
                "-pix_fmt",
                "rgb24",
                "pipe:1",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
        assert rgb[2] > 200 and rgb[0] < 30  # Blue after the 1-second transition.
        pcm = subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-i",
                str(result.path),
                "-t",
                "0.25",
                "-vn",
                "-ar",
                "8000",
                "-ac",
                "1",
                "-f",
                "s16le",
                "pipe:1",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
        samples = struct.unpack("<" + "h" * (len(pcm) // 2), pcm)
        crossings = sum(a <= 0 < b for a, b in zip(samples, samples[1:], strict=False))
        assert abs(crossings / (len(samples) / 8000) - 880) < 20


@media_test
def test_strict_mode_preserves_24fps_input_and_rejects_other_rates(tmp_path):
    source = make_clip(tmp_path, "24")
    with prepare(source, start_time=1, mode="strict") as result:
        assert result.path == source and result.start_time == 1
    with pytest.raises(ValueError, match="严格模式"):
        with prepare(make_clip(tmp_path, "30"), mode="strict"):
            pass


@media_test
def test_short_missing_audio_and_invalid_media_fail_before_submission(tmp_path):
    for source, message in [
        (make_clip(tmp_path, duration=2), "不足"),
        (make_clip(tmp_path, audio=False), "音轨"),
    ]:
        with pytest.raises(ValueError, match=message):
            with prepare(source):
                pass
    invalid = tmp_path / "invalid.mp4"
    invalid.write_bytes(b"not a video")
    with pytest.raises(ValueError, match="无法读取"):
        with prepare(invalid):
            pass
    with pytest.raises(ValueError, match="不足"):
        with prepare(make_clip(tmp_path, "25"), start_time=3):
            pass


def test_adaptation_is_pinned_and_does_not_change_other_workflows(monkeypatch):
    def no_probe(*args, **kwargs):
        pytest.fail("other workflows must not require FFmpeg")

    monkeypatch.setattr(video, "inspect_video", no_probe)
    with video.prepare_reference_video("vgen/other", "1.0.0", "a" * 64, None) as result:
        assert result is None
    with pytest.raises(ValueError, match="摘要"):
        with video.prepare_reference_video(*video.H3_FACE_RELEASE, "0" * 64, "video.mp4"):
            pass


def test_legacy_face_release_remains_digest_pinned(monkeypatch):
    monkeypatch.setattr(
        video,
        "inspect_video",
        lambda path, start_time=0: video.VideoInfo(Fraction(24), Fraction(6), False, True),
    )
    legacy = ("vgen/minimax-h3-face-reference", "1.0.0")
    digest = video.H3_FACE_RELEASE_DIGESTS[legacy]
    with video.prepare_reference_video(*legacy, digest, "video.mp4", mode="strict") as result:
        assert result is not None and result.mode == "strict"


def test_missing_ffmpeg_is_actionable(monkeypatch):
    monkeypatch.setattr(video.shutil, "which", lambda name: None)
    with pytest.raises(ValueError, match="安装 FFmpeg"):
        video._binary("ffprobe")


@media_test
def test_cli_preflight_reports_media_locally_without_transcoding_or_exposing_it(
    tmp_path, monkeypatch, capsys
):
    source = make_clip(tmp_path, "30000/1001")
    manifest = WorkflowManifest.load(PACKAGE / "manifest.yaml")
    calls = []

    class Client:
        profile = SimpleNamespace(default_workspace="workspace", default_pool="GPU")

        def preflight_task(self, payload):
            calls.append(payload)
            assert "private" not in json.dumps(payload)
            assert "source_fps" not in json.dumps(payload)
            return {"ready": True, "state": "ready"}

        def close(self):
            pass

    monkeypatch.setattr(cli, "_client", lambda profile: Client())
    monkeypatch.setattr(cli, "_resolve_pool_id", lambda *args, **kwargs: "pool")
    monkeypatch.setattr(
        cli, "_resolve_workflow", lambda ref: (manifest, PACKAGE, video.H3_FACE_DIGEST)
    )
    original_run = video._run

    def probe_only(command, **kwargs):
        assert Path(command[0]).name == "ffprobe"
        return original_run(command, **kwargs)

    monkeypatch.setattr(video, "_run", probe_only)
    argv = [
        "task",
        "preflight",
        "--workflow",
        "h3-face",
        "--image",
        "private-face.png",
        "--video",
        str(source),
    ]
    cli.dispatch(cli.build_parser().parse_args(argv))
    report = json.loads(capsys.readouterr().out)
    assert report["video_input"]["source_fps_ratio"] == "30000/1001"
    assert report["video_input"]["model_fps"] == 24
    assert len(calls) == 1
    with pytest.raises(ValueError, match="严格模式"):
        cli.dispatch(cli.build_parser().parse_args([*argv, "--video-fps-mode", "strict"]))
    assert len(calls) == 1


@media_test
def test_cli_submit_uploads_normalized_clip_and_cleans_it_on_failure(tmp_path, monkeypatch):
    source = make_clip(tmp_path, "25")
    face = tmp_path / "face.png"
    face.write_bytes(b"image")
    manifest = WorkflowManifest.load(PACKAGE / "manifest.yaml")
    processed = []

    class StopAfterInputs(Exception):
        pass

    class Client:
        profile = SimpleNamespace(default_workspace="workspace", default_pool="GPU")

        def prepare_task(self, payload, **kwargs):
            assert (
                payload["input_artifacts"][1]["media_metadata"]["filename"] == "reference-video.mp4"
            )
            return {"id": "task", "attempt_id": "attempt", "worker": {}}

        def close(self):
            pass

    def capture_inputs(inputs, *args, **kwargs):
        clip = next(item for item in inputs if item.name == "video")
        assert clip.path != source
        assert video.inspect_video(clip.path).constant_24fps
        processed.append(clip.path)
        raise StopAfterInputs

    real_build = build_comfy_graph

    def capture_graph(template, mapping, parameters):
        assert parameters["start_time"] == 0
        graph, effective, operation = real_build(template, mapping, parameters)
        assert graph["3"]["inputs"]["start_time"] == 0
        return graph, effective, operation

    monkeypatch.setattr(cli, "_client", lambda profile: Client())
    monkeypatch.setattr(cli, "_resolve_pool_id", lambda *args, **kwargs: "pool")
    monkeypatch.setattr(
        cli, "_resolve_workflow", lambda ref: (manifest, PACKAGE, video.H3_FACE_DIGEST)
    )
    monkeypatch.setattr(cli, "_verify_prepared_worker_certificate", lambda *args: None)
    monkeypatch.setattr(cli, "_verify_prepared_allocation", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "encrypt_and_upload_inputs", capture_inputs)
    monkeypatch.setattr(cli, "build_comfy_graph", capture_graph)
    with pytest.raises(StopAfterInputs):
        cli.dispatch(
            cli.build_parser().parse_args(
                [
                    "task",
                    "submit",
                    "test",
                    "--workflow",
                    "h3-face",
                    "--image",
                    str(face),
                    "--video",
                    str(source),
                    "-p",
                    "start_time=1",
                ]
            )
        )
    assert processed and not processed[0].exists()
    assert source.exists()
