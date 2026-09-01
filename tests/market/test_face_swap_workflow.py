from __future__ import annotations

import json
from pathlib import Path

from vgen.executors.comfyui import _workflow_capability
from vgen.market.builder import build_comfy_graph
from vgen.market.registry import WorkflowRegistry, build_archive
from vgen.worker.capabilities import WorkerCapabilityStore

PACKAGE = Path(__file__).parents[2] / "workflows/vgen/minimax-h3-face-reference/2.0.1"


def test_face_swap_release_preserves_video_pipeline_and_pins_dependencies(tmp_path: Path) -> None:
    archive = build_archive(PACKAGE, tmp_path / "workflow.zip", allow_unsigned=True)
    installed = WorkflowRegistry(tmp_path / "registry").install(archive, allow_unsigned=True)
    WorkerCapabilityStore._validate_inert_workflow(installed)
    capability = _workflow_capability(installed)

    assert capability.operations == {"v2v"}
    assert capability.executor_min_version == "1.3.0"
    assert capability.custom_nodes[0].node_types == {"VGenTemporalFaceSwap"}
    assert capability.custom_nodes[0].node_pack == "vgen/comfyui-temporal-face-swap@1.0.1"
    assert capability.policy.model_files[0].path == "face_landmarkers/face_landmarker.task"

    graph, effective, operation = build_comfy_graph(
        capability.template_graph,
        capability.mapping,
        {
            "prompt": "Authorized single-face replacement.",
            "image": "face.png",
            "video": "reference.mp4",
            "seed": 1234,
            "start_time": 0,
            "strength": 1,
            "identity_shape": 0.3,
            "feather": 0.045,
        },
    )
    assert operation == "v2v"
    assert effective["seed"] == 1234
    assert graph["5"]["class_type"] == "VGenTemporalFaceSwap"
    assert graph["5"]["inputs"]["source_image"] == ["1", 0]
    assert graph["5"]["inputs"]["target_images"] == ["4", 0]
    assert graph["6"]["inputs"]["audio"] == ["4", 1]
    assert not any("MiniMax" in node["class_type"] for node in graph.values())
    assert "minimax_h3" not in json.dumps(graph).lower()
