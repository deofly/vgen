from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from vgen.cli.main import _effective_parameters, _local_task_inputs, build_parser
from vgen.crypto import canonical_json
from vgen.executors import ExecutorFailure
from vgen.executors.comfyui import (
    ComfyUIExecutionPolicy,
    ComfyUIExecutor,
    _capability_expected_bindings,
    _workflow_capability,
)
from vgen.gateway.public_metadata import canonical_worker_capabilities
from vgen.gateway.schemas import CapabilityInstallSpec
from vgen.market.builder import WorkflowBuildError, build_comfy_graph
from vgen.market.registry import WorkflowRegistry, build_archive
from vgen.worker.capabilities import WorkerCapabilityStore

PACKAGE = Path(__file__).parents[2] / "workflows/vgen/minimax-h3-face-reference/1.0.1"


def test_market_archive_builds_exact_video_capability_and_rejects_tampering(tmp_path: Path) -> None:
    archive = build_archive(PACKAGE, tmp_path / "workflow.zip", allow_unsigned=True)
    installed = WorkflowRegistry(tmp_path / "registry").install(archive, allow_unsigned=True)
    WorkerCapabilityStore._validate_inert_workflow(installed)
    capability = _workflow_capability(installed)
    assert capability.operations == {"v2v"}
    assert capability.executor_min_version == "1.3.0"
    args = build_parser().parse_args(
        [
            "task",
            "submit",
            "Use <Picture 1> for identity and <Video 1> for motion.",
            "--image",
            "face.png",
            "--video",
            "reference.mp4",
        ]
    )
    params = _effective_parameters(installed.manifest, args)
    graph, effective, operation = build_comfy_graph(
        capability.template_graph, capability.mapping, params
    )
    bindings = _capability_expected_bindings(graph, capability.mapping, effective)
    assert {item["input"] for item in bindings} == {"image", "video"}
    assert operation == "v2v"
    capability.policy.authorize_graph(graph, bindings)
    ComfyUIExecutor._authorize_capability_payload(capability, operation, graph, bindings, effective)
    for bad_operation, bad_bindings, reason in [
        ("i2v", bindings, "workflow_operation_mismatch"),
        ("v2v", bindings[:1], "workflow_bindings_mismatch"),
    ]:
        with pytest.raises(ExecutorFailure) as caught:
            ComfyUIExecutor._authorize_capability_payload(
                capability, bad_operation, graph, bad_bindings, effective
            )
        assert caught.value.details == {"reason": reason}
    graph["147"]["inputs"]["file"] = "another-existing-file.mp4"
    with pytest.raises(ExecutorFailure) as caught:
        ComfyUIExecutor._authorize_capability_payload(
            capability, operation, graph, bindings, effective
        )
    assert caught.value.details == {"reason": "workflow_graph_mismatch"}


def test_cli_uploads_video_as_an_encrypted_artifact_without_private_basename(
    tmp_path: Path,
) -> None:
    image = tmp_path / "private-person.png"
    video = tmp_path / "private-project.mp4"
    image.write_bytes(b"image")
    video.write_bytes(b"video")
    args = build_parser().parse_args(
        ["task", "submit", "reference", "--image", str(image), "--video", str(video)]
    )
    inputs = _local_task_inputs(args)
    assert [item.name for item in inputs] == ["image", "video"]
    descriptor = inputs[1].prepare_descriptor()
    assert descriptor["media_metadata"] == {
        "filename": "reference-video.mp4",
        "media_type": "video/mp4",
    }
    assert "private" not in json.dumps(descriptor)
    assert descriptor["encrypted_size"] > video.stat().st_size


@pytest.mark.parametrize(
    "extra", [[], ["-p", "video=existing.mp4"], ["--video", "clip.mp4", "-p", "width=4096"]]
)
def test_face_reference_rejects_missing_video_path_bypass_and_oversize(extra: list[str]) -> None:
    from vgen.market.models import WorkflowManifest

    manifest = WorkflowManifest.load(PACKAGE / "manifest.yaml")
    args = build_parser().parse_args(["task", "submit", "reference", "--image", "face.png", *extra])
    with pytest.raises(ValueError):
        _effective_parameters(manifest, args)


@pytest.mark.parametrize(
    ("loader", "field", "bindings", "reason"),
    [
        ("LoadVideo", "file", [], "unbound_load_video"),
        (
            "LoadVideo",
            "image",
            [{"input": "video", "node_id": "1", "field": "image"}],
            "input_binding_target_not_allowed",
        ),
        (
            "LoadImage",
            "file",
            [{"input": "video", "node_id": "1", "field": "file"}],
            "input_binding_target_not_allowed",
        ),
        (
            "LoadVideo",
            "file",
            [{"input": "video", "node_id": "1", "field": "file"}] * 2,
            "duplicate_input_binding",
        ),
    ],
)
def test_video_binding_is_limited_to_exact_native_loader_pair(
    loader, field, bindings, reason
) -> None:
    policy = ComfyUIExecutionPolicy(allowed_node_classes=frozenset({loader}))
    graph = {"1": {"class_type": loader, "inputs": {field: "existing.mp4"}}}
    with pytest.raises(ExecutorFailure) as caught:
        policy.authorize_graph(graph, bindings)
    assert caught.value.details == {"reason": reason}


def test_video_reference_cannot_silently_select_first_last_frame_operation() -> None:
    graph = {
        "1": {"class_type": "LoadVideo", "inputs": {"file": "reference.mp4"}},
        "2": {"class_type": "LoadImage", "inputs": {"image": "last.png"}},
    }
    mapping = {
        "video": {"node": "1", "input": "file"},
        "last_image": {"node": "2", "input": "image"},
    }
    with pytest.raises(WorkflowBuildError, match="video and last_image"):
        build_comfy_graph(graph, mapping, {"video": "ref.mp4", "last_image": "end.png"})


def test_video_workflow_passes_gateway_maintenance_and_heartbeat_contracts() -> None:
    spec = CapabilityInstallSpec(
        kind="capability_install",
        workflow_ref="vgen/minimax-h3-face-reference@1.0.1",
        workflow_digest="sha256:" + "a" * 64,
        artifact_sha256="b" * 64,
        artifact_size=100,
        node_classes_digest=sha256(canonical_json(["LoadVideo", "Video Slice"])).hexdigest(),
        model_digests=[],
        node_classes=["LoadVideo", "Video Slice"],
        publisher_key=None,
        allow_unsigned_workflow=True,
    )
    assert spec.node_classes == ["LoadVideo", "Video Slice"]
    result = canonical_worker_capabilities(
        {"executors": [{"type": "comfyui", "version": "1.3.0", "operations": ["v2v"]}]},
        executor_type="comfyui",
    )
    assert result["executors"][0]["operations"] == ["v2v"]


@pytest.mark.parametrize("node_class", ["Video Slice\n", "Video\tSlice", "Arbitrary Spaced Class"])
def test_native_video_slice_exception_does_not_admit_other_whitespace(node_class: str) -> None:
    policy = ComfyUIExecutionPolicy(allowed_node_classes=frozenset({node_class}))
    with pytest.raises(ExecutorFailure) as caught:
        policy.authorize_graph({"1": {"class_type": node_class, "inputs": {}}}, [])
    assert caught.value.details == {"reason": "invalid_node_class"}
