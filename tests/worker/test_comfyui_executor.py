from __future__ import annotations

import json
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import websocket

import vgen.executors.comfyui as comfyui_module
from vgen.artifacts import ArtifactDescriptor
from vgen.executors import ExecutionContext, ExecutionInput, ExecutionRequest, ExecutorFailure
from vgen.executors.comfyui import (
    COMFYUI_PAYLOAD_FORMAT,
    ComfyOutput,
    ComfyRunResult,
    ComfyUIClient,
    ComfyUIExecutionPolicy,
    ComfyUIExecutor,
    ComfyUIPolicyError,
    _ComfyProtocolError,
    _probe_media,
)
from vgen.market.builder import build_comfy_graph
from vgen.market.registry import package_digest
from vgen.protocol import ErrorCode


class FakeComfyClient:
    def __init__(self, output: Path) -> None:
        self.output = output
        self.workflow: dict[str, Any] | None = None
        self.uploaded: list[tuple[Path, str]] = []
        self.interrupted = False

    def ping(self) -> None:
        return None

    def gpu_info(self) -> list[dict[str, Any]]:
        return [{"name": "fake", "vram_total_mb": 100}]

    def models_catalog(self) -> set[str]:
        return {"model.safetensors"}

    def system_info(self) -> dict[str, Any]:
        return {
            "ram_bytes": 1024 * 1024 * 1024,
            "os": "test",
            "runtime_version": "0.30.1",
        }

    def upload_image(self, path: Path, name: str) -> tuple[str, str]:
        self.uploaded.append((path, name))
        return "staged.png", "vgen"

    def run(
        self,
        workflow: dict[str, Any],
        on_progress: Any,
        should_cancel: Any,
        timeout: float,
    ) -> ComfyRunResult:
        self.workflow = workflow
        assert should_cancel() is False
        assert timeout == 30
        on_progress(0.5, "sampling")
        self.output.write_bytes(b"video")
        return ComfyRunResult(
            "prompt_1",
            (ComfyOutput(self.output.name, "", "output"),),
        )

    def interrupt(self) -> None:
        self.interrupted = True


class _PromptResponse:
    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return self._body


class _PromptSession:
    def __init__(self, response: _PromptResponse) -> None:
        self._response = response

    def post(self, *_args: Any, **_kwargs: Any) -> _PromptResponse:
        return self._response


class _MessageWebSocket:
    def __init__(self, *messages: str | bytes) -> None:
        self._messages = list(messages)

    def recv(self) -> str | bytes:
        return self._messages.pop(0)


class _ClosedWebSocket:
    def recv(self) -> str:
        raise websocket.WebSocketConnectionClosedException()


def _policy(
    *classes: str,
    custom: tuple[str, ...] = (),
    digests: tuple[str, ...] = (),
    max_nodes: int = 64,
) -> ComfyUIExecutionPolicy:
    return ComfyUIExecutionPolicy(
        allowed_node_classes=frozenset(classes),
        allowed_custom_node_classes=frozenset(custom),
        allowed_workflow_digests=frozenset(digests),
        max_nodes=max_nodes,
    )


def _request(payload: bytes, *, digest: str = "a" * 64) -> ExecutionRequest:
    return ExecutionRequest(
        "tsk_1",
        "att_1",
        digest,
        "t2v",
        COMFYUI_PAYLOAD_FORMAT,
        payload,
        timeout_seconds=30,
    )


@pytest.mark.parametrize(
    ("exception_type", "message", "reason", "code"),
    [
        (
            "torch.OutOfMemoryError",
            "CUDA out of memory",
            "gpu_out_of_memory",
            ErrorCode.GPU_OUT_OF_MEMORY,
        ),
        (
            "RuntimeError",
            "The size of tensor a must match the size of tensor b",
            "tensor_shape_mismatch",
            ErrorCode.DEPENDENCY_MISSING,
        ),
        (
            "RuntimeError",
            "DefaultCPUAllocator: cannot allocate memory",
            "system_out_of_memory",
            ErrorCode.SYSTEM_OUT_OF_MEMORY,
        ),
        (
            "MemoryError",
            "allocation failed",
            "system_out_of_memory",
            ErrorCode.SYSTEM_OUT_OF_MEMORY,
        ),
        (
            "RuntimeError",
            "std::bad_alloc",
            "system_out_of_memory",
            ErrorCode.SYSTEM_OUT_OF_MEMORY,
        ),
        (
            "ModuleNotFoundError",
            "No module named custom_dependency",
            "python_dependency_missing",
            ErrorCode.DEPENDENCY_MISSING,
        ),
        (
            "SafetensorError",
            "invalid header while loading checkpoint",
            "model_load_incompatible",
            ErrorCode.DEPENDENCY_MISSING,
        ),
        (
            "RuntimeError",
            "kernel launch failed",
            "node_runtime_error",
            ErrorCode.DEPENDENCY_MISSING,
        ),
    ],
)
def test_comfyui_execution_errors_are_fixed_classifications_without_upstream_leaks(
    exception_type: str,
    message: str,
    reason: str,
    code: ErrorCode,
) -> None:
    secret = "private prompt token=super-secret C:/Users/private/model.gguf"
    raw = json.dumps(
        {
            "type": "execution_error",
            "data": {
                "prompt_id": "prompt_1",
                "node_id": "405:344",
                "node_type": "SamplerCustomAdvanced",
                "exception_type": exception_type,
                "exception_message": f"{message}; {secret}",
                "traceback": [secret],
                "current_inputs": {"prompt": secret},
                "current_outputs": {"path": secret},
            },
        }
    )
    client = ComfyUIClient("http://127.0.0.1:8188")

    with pytest.raises(_ComfyProtocolError) as raised:
        client._wait(_MessageWebSocket(raw), "prompt_1", lambda *_args: None, lambda: False, 5)

    protocol_error = raised.value
    failure = ComfyUIExecutor._map_protocol_error(protocol_error)
    assert failure.code == code
    assert dict(failure.details) == {
        "reason": reason,
        "component": "sampler",
    }
    if reason == "system_out_of_memory":
        assert failure.retry_action.value == "another_worker"
    assert secret not in str(protocol_error)
    assert secret not in str(failure)
    assert secret not in json.dumps(vars(protocol_error), default=str)
    assert secret not in json.dumps(dict(failure.details))


@pytest.mark.parametrize(
    ("node_id", "node_type", "expected_component"),
    [
        ("405:344\nprivate", "SamplerCustomAdvanced", "sampler"),
        ("C:/Users/private/token", "PrivateSecret", None),
        ("U0VDUkVUX1BST01QVA", "EncodedSecret", None),
        ("x" * 200, "ModelLoaderWithPrivateSuffix", "model_loader"),
    ],
)
def test_comfyui_execution_error_exposes_only_a_fixed_component_role(
    node_id: str,
    node_type: str,
    expected_component: str | None,
) -> None:
    secret = "private"
    raw = json.dumps(
        {
            "type": "execution_error",
            "data": {
                "prompt_id": "prompt_1",
                "node_id": node_id,
                "node_type": node_type,
                "exception_type": "RuntimeError",
                "exception_message": f"kernel failure {secret}",
            },
        }
    )
    client = ComfyUIClient("http://127.0.0.1:8188")

    with pytest.raises(_ComfyProtocolError) as raised:
        client._wait(_MessageWebSocket(raw), "prompt_1", lambda *_args: None, lambda: False, 5)

    details = raised.value.safe_details()
    assert "node_id" not in details
    assert "node_type" not in details
    assert details.get("component") == expected_component
    assert secret not in json.dumps(details)


@pytest.mark.parametrize(
    ("error", "expected_reason"),
    [
        (
            {
                "type": "value_not_in_list",
                "message": "Value not in list",
                "extra_info": {"input_name": "model_name"},
            },
            "model_not_found",
        ),
        (
            {"type": "required_input_missing", "message": "Required input is missing"},
            "node_validation_failed",
        ),
        (
            {"type": "invalid_node", "message": "Node does not exist"},
            "node_class_missing",
        ),
    ],
)
def test_comfyui_http_400_node_errors_are_safely_classified(
    error: dict[str, Any],
    expected_reason: str,
) -> None:
    secret = "private prompt https://example.invalid/?token=super-secret C:/private"
    body = {
        "error": {"type": "prompt_outputs_failed_validation", "message": secret},
        "node_errors": {
            "405:371": {
                "class_type": "LatentUpscaleModelLoader",
                "errors": [{**error, "details": secret}],
            }
        },
    }
    client = ComfyUIClient(
        "http://127.0.0.1:8188", session=_PromptSession(_PromptResponse(400, body))
    )

    with pytest.raises(_ComfyProtocolError) as raised:
        client._submit({"1": {"inputs": {"prompt": secret}}}, "client_1")

    failure = ComfyUIExecutor._map_protocol_error(raised.value)
    assert failure.code == ErrorCode.DEPENDENCY_MISSING
    assert failure.retry_action.value == "same_worker"
    assert dict(failure.details) == {
        "reason": expected_reason,
        "component": "model_loader",
    }
    assert secret not in str(raised.value)
    assert secret not in json.dumps(vars(raised.value), default=str)
    assert secret not in json.dumps(dict(failure.details))


@pytest.mark.parametrize("closed_message", [None, "", b""])
def test_comfyui_websocket_disconnect_history_fallback_surfaces_execution_failure(
    monkeypatch: pytest.MonkeyPatch,
    closed_message: str | bytes | None,
) -> None:
    secret = "private prompt token=super-secret C:/private/model.gguf"
    history = {
        "status": {
            "status_str": "error",
            "completed": False,
            "messages": [
                [
                    "execution_error",
                    {
                        "node_id": "405:344",
                        "node_type": "SamplerCustomAdvanced",
                        "exception_type": "RuntimeError",
                        "exception_message": f"shape mismatch; {secret}",
                        "traceback": [secret],
                        "current_inputs": {"prompt": secret},
                    },
                ]
            ],
        },
        "outputs": {},
    }
    client = ComfyUIClient("http://127.0.0.1:8188")
    monkeypatch.setattr(client, "_history", lambda _prompt_id: history)
    ws = _MessageWebSocket(closed_message) if closed_message is not None else _ClosedWebSocket()

    with pytest.raises(_ComfyProtocolError) as raised:
        client._wait(ws, "prompt_1", lambda *_args: None, lambda: False, 5)

    assert raised.value.safe_details() == {
        "reason": "tensor_shape_mismatch",
        "component": "sampler",
    }
    assert secret not in str(raised.value)
    assert secret not in json.dumps(vars(raised.value), default=str)


def test_media_probe_uses_opencv_when_ffprobe_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeCapture:
        def isOpened(self) -> bool:
            return True

        def get(self, field: int) -> float:
            return {1: 81, 2: 24, 3: 1280, 4: 720}[field]

        def release(self) -> None:
            return None

    fake_cv2 = SimpleNamespace(
        VideoCapture=lambda _path: FakeCapture(),
        CAP_PROP_FRAME_COUNT=1,
        CAP_PROP_FPS=2,
        CAP_PROP_FRAME_WIDTH=3,
        CAP_PROP_FRAME_HEIGHT=4,
    )
    monkeypatch.setattr("vgen.executors.comfyui.shutil.which", lambda _name: None)
    monkeypatch.setitem(sys.modules, "cv2", fake_cv2)

    assert _probe_media(tmp_path / "result.mp4") == {
        "width": 1280,
        "height": 720,
        "frames": 81,
        "duration_ms": 3375,
    }


def test_comfyui_executor_keeps_graph_inside_adapter(tmp_path: Path) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    client = FakeComfyClient(output_dir / "result.mp4")
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        policy=_policy("LoadImage"),
    )
    first_frame = tmp_path / "first.png"
    first_frame.write_bytes(b"image")
    payload = json.dumps(
        {
            "workflow": {
                "1": {
                    "class_type": "LoadImage",
                    "inputs": {"image": "default.png"},
                    "_meta": {"title": "INPUT_IMAGE"},
                }
            },
            "input_bindings": [
                {"input": "first_frame", "node_title": "INPUT_IMAGE", "field": "image"}
            ],
        }
    ).encode()
    progress = []
    result = executor.execute(
        ExecutionRequest(
            "tsk_1",
            "att_1",
            "a" * 64,
            "i2v",
            COMFYUI_PAYLOAD_FORMAT,
            payload,
            inputs=(
                ExecutionInput(
                    "first_frame",
                    first_frame,
                    ArtifactDescriptor("art_1", "first.png"),
                ),
            ),
            timeout_seconds=30,
        ),
        ExecutionContext(tmp_path / "work", progress.append),
    )
    assert client.workflow is not None
    assert client.workflow["1"]["inputs"]["image"] == "vgen/staged.png"
    assert result.artifacts[0].path == output_dir / "result.mp4"
    assert result.executor_run_id == "prompt_1"
    assert result.usage.gpu_active_ms is None
    assert result.usage.output_bytes == 5
    assert progress[0].fraction == 0.5
    assert executor.descriptor().max_concurrency == 1
    assert executor.health().healthy
    assert "models" not in executor.capabilities()
    assert executor.capabilities()["vram_bytes"] == 100 * 1024 * 1024
    assert executor.capabilities()["ram_bytes"] == 1024 * 1024 * 1024
    assert executor.capabilities()["runtime_version"] == "0.30.1"


def test_comfyui_executor_rejects_non_api_payload_without_leaking_it(tmp_path: Path) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=FakeComfyClient(output_dir / "result.mp4"),
        policy=_policy("LoadImage"),
    )
    secret = b'{"prompt":"private prompt"}'
    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(
            ExecutionRequest(
                "tsk_1",
                "att_1",
                "a" * 64,
                "t2v",
                COMFYUI_PAYLOAD_FORMAT,
                secret,
            ),
            ExecutionContext(tmp_path / "work"),
        )
    assert raised.value.code == ErrorCode.UNSUPPORTED_PAYLOAD
    assert "private prompt" not in str(raised.value)


def test_comfyui_executor_requires_local_policy_before_parsing_remote_graph(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    client = FakeComfyClient(output_dir / "result.mp4")
    executor = ComfyUIExecutor("http://127.0.0.1:8188", output_dir, client=client)
    private = b'{"workflow":{"1":{"class_type":"LoadImage","inputs":{"prompt":"secret"}}}}'

    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(_request(private), ExecutionContext(tmp_path / "work"))

    assert raised.value.code == ErrorCode.EXECUTOR_UNAVAILABLE
    assert raised.value.responsibility == "provider"
    assert raised.value.retry_action.value == "same_worker"
    assert raised.value.details == {"reason": "policy_required"}
    assert "secret" not in str(raised.value)
    assert client.workflow is None
    assert executor.capabilities()["execution_policy"] == {
        "configured": False,
        "model_pins": 0,
        "models_verified": 0,
        "models_failed": 0,
    }


def test_comfyui_executor_maps_local_memory_error_to_system_oom(tmp_path: Path) -> None:
    class MemoryFailingClient(FakeComfyClient):
        def run(self, *args: Any, **kwargs: Any) -> ComfyRunResult:
            raise MemoryError

    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=MemoryFailingClient(output_dir / "result.mp4"),
        policy=_policy("SafeNode"),
    )
    payload = json.dumps({"workflow": {"1": {"class_type": "SafeNode", "inputs": {}}}}).encode()

    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(_request(payload), ExecutionContext(tmp_path / "work"))

    assert raised.value.code == ErrorCode.SYSTEM_OUT_OF_MEMORY
    assert raised.value.responsibility == "provider"
    assert raised.value.retry_action.value == "another_worker"
    assert raised.value.details == {"reason": "system_out_of_memory"}


def test_comfyui_output_escape_is_a_provider_environment_failure(tmp_path: Path) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=FakeComfyClient(output_dir / "result.mp4"),
    )

    with pytest.raises(ExecutorFailure) as raised:
        executor._resolve_output(ComfyOutput("secret.mp4", "../outside", "output"))

    assert raised.value.code == ErrorCode.EXECUTOR_UNAVAILABLE
    assert raised.value.responsibility == "provider"
    assert raised.value.retry_action.value == "same_worker"
    assert raised.value.details == {"reason": "output_path_outside_root"}


def test_comfyui_executor_rejects_unknown_dangerous_node_without_leaking_class(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    client = FakeComfyClient(output_dir / "result.mp4")
    secret_class = "ExecuteShell_private_secret"
    payload = json.dumps(
        {
            "workflow": {
                "1": {"class_type": secret_class, "inputs": {"command": "id"}},
            }
        }
    ).encode()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        policy=_policy("LoadImage"),
    )

    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(_request(payload), ExecutionContext(tmp_path / "work"))

    assert raised.value.details == {"reason": "node_class_not_allowed"}
    assert secret_class not in str(raised.value)
    assert secret_class not in json.dumps(dict(raised.value.details))
    assert client.workflow is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("image", "../../private.png"),
        ("input_image", "../private.png"),
        ("model_name", "/etc/passwd"),
        ("vae_name", "C:\\Windows\\secret.safetensors"),
        ("filename_prefix", "file:///tmp/private"),
        ("output_path", "https://attacker.example/output"),
        ("lora_name", "models/evil\x00.safetensors"),
        ("ckpt_name", "models/%2e%2e/private.safetensors"),
    ],
)
def test_comfyui_executor_rejects_path_escape_in_path_semantic_fields(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    client = FakeComfyClient(output_dir / "result.mp4")
    payload = json.dumps(
        {"workflow": {"1": {"class_type": "SafeNode", "inputs": {field: value}}}}
    ).encode()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        policy=_policy("SafeNode"),
    )

    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(_request(payload), ExecutionContext(tmp_path / "work"))

    assert raised.value.details == {"reason": "unsafe_local_path"}
    assert value not in str(raised.value)
    assert client.workflow is None


def test_comfyui_executor_does_not_treat_prompt_text_as_a_path(tmp_path: Path) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    client = FakeComfyClient(output_dir / "result.mp4")
    prompt = "show /tmp/example, ../ as text, and https://example.test without opening it"
    payload = json.dumps(
        {"workflow": {"1": {"class_type": "PromptNode", "inputs": {"prompt": prompt}}}}
    ).encode()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        policy=_policy("PromptNode"),
    )

    executor.execute(_request(payload), ExecutionContext(tmp_path / "work"))

    assert client.workflow is not None
    assert client.workflow["1"]["inputs"]["prompt"] == prompt


def test_comfyui_executor_rejects_oversized_or_cyclic_graph(tmp_path: Path) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    client = FakeComfyClient(output_dir / "result.mp4")
    oversized = json.dumps(
        {
            "workflow": {
                "1": {"class_type": "SafeNode", "inputs": {}},
                "2": {"class_type": "SafeNode", "inputs": {}},
            }
        }
    ).encode()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        policy=_policy("SafeNode", max_nodes=1),
    )
    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(_request(oversized), ExecutionContext(tmp_path / "work-a"))
    assert raised.value.details == {"reason": "graph_node_limit"}

    cyclic = json.dumps(
        {
            "workflow": {
                "1": {"class_type": "SafeNode", "inputs": {"source": ["2", 0]}},
                "2": {"class_type": "SafeNode", "inputs": {"source": ["1", 0]}},
            }
        }
    ).encode()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        policy=_policy("SafeNode"),
    )
    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(_request(cyclic), ExecutionContext(tmp_path / "work-b"))
    assert raised.value.details == {"reason": "cyclic_graph"}
    assert client.workflow is None


def test_comfyui_input_binding_must_target_declared_load_image(tmp_path: Path) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    client = FakeComfyClient(output_dir / "result.mp4")
    payload = json.dumps(
        {
            "workflow": {
                "1": {
                    "class_type": "PromptNode",
                    "inputs": {"prompt": "safe"},
                    "_meta": {"title": "NOT_AN_IMAGE"},
                }
            },
            "input_bindings": [
                {"input": "first_frame", "node_title": "NOT_AN_IMAGE", "field": "image"}
            ],
        }
    ).encode()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        policy=_policy("PromptNode"),
    )
    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(_request(payload), ExecutionContext(tmp_path / "work"))
    assert raised.value.details == {"reason": "input_binding_target_not_allowed"}
    assert not client.uploaded


def test_comfyui_executor_rejects_unbound_load_image_local_file_read(tmp_path: Path) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    client = FakeComfyClient(output_dir / "result.mp4")
    payload = json.dumps(
        {
            "workflow": {
                "1": {
                    "class_type": "LoadImage",
                    "inputs": {"image": "existing-local-input.png"},
                }
            }
        }
    ).encode()
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        policy=_policy("LoadImage"),
    )

    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(_request(payload), ExecutionContext(tmp_path / "work"))

    assert raised.value.details == {"reason": "unbound_load_image"}
    assert client.workflow is None


def test_minimax_h3_reference_graph_passes_explicit_builtin_and_custom_policy(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    client = FakeComfyClient(output_dir / "result.mp4")
    package_path = Path(__file__).parents[2] / "workflows/vgen/minimax-h3-8step/1.0.0"
    workflow_path = package_path / "workflow.json"
    template = json.loads(workflow_path.read_text(encoding="utf-8"))
    mapping = json.loads((package_path / "mapping.json").read_text(encoding="utf-8"))
    workflow, _, operation = build_comfy_graph(
        template,
        mapping,
        {
            "prompt": "reference policy acceptance",
            "seed": 1,
            "steps": 8,
            "width": 768,
            "height": 1344,
            "frames": 39,
            "fps": 24,
        },
    )
    assert operation == "t2v"
    digest = "sha256:bd15cace959f6330626b47c07195b6f8a016e334683969c0d5b044b24debcb93"
    assert digest == f"sha256:{package_digest(package_path)}"
    policy = ComfyUIExecutionPolicy.load(
        Path(__file__).parents[2] / "examples/comfyui-minimax-h3-policy.yaml"
    )
    assert len(policy.model_files) == 5
    assert policy.maintenance_workflows == (("vgen/minimax-h3-8step@1.0.0", digest),)
    assert all(not pin.gated and not pin.manual_download for pin in policy.model_files)
    assert all(pin.source and pin.revision and pin.license for pin in policy.model_files)
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        # This contract test validates the graph policy without materializing
        # the roughly 44 GB production model set in the test workspace.
        policy=replace(policy, model_files=()),
    )
    payload = json.dumps({"workflow": workflow}).encode()

    executor.execute(
        _request(payload, digest=digest),
        ExecutionContext(tmp_path / "work"),
    )

    assert client.workflow is not None
    assert len(client.workflow) == 12
    assert "MiniMaxH3AudioConditioningT8" in policy.allowed_custom_node_classes
    assert "LoraLoaderBypassModelOnly" in policy.allowed_node_classes


def test_comfyui_model_pins_are_verified_before_advertising_or_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "outputs"
    model_root = tmp_path / "models"
    output_dir.mkdir()
    (model_root / "diffusion_models").mkdir(parents=True)
    model = model_root / "diffusion_models/model.safetensors"
    contents = b"trusted-model"
    model.write_bytes(contents)
    verified_metadata = model.stat()
    monkeypatch.setattr(
        comfyui_module.time,
        "time_ns",
        lambda: max(verified_metadata.st_mtime_ns, verified_metadata.st_ctime_ns) + 1,
    )
    digest = sha256(contents).hexdigest()
    policy = ComfyUIExecutionPolicy.from_mapping(
        {
            "version": 1,
            "allowed_node_classes": ["SafeNode"],
            "models": [
                {
                    "path": "diffusion_models/model.safetensors",
                    "sha256": f"sha256:{digest}",
                    "size": len(contents),
                }
            ],
        }
    )
    client = FakeComfyClient(output_dir / "result.mp4")
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=client,
        policy=policy,
        model_root=model_root,
    )

    capabilities = executor.capabilities()
    assert capabilities["model_digests"] == [f"sha256:{digest}"]
    assert capabilities["execution_policy"]["models_verified"] == 1

    model.write_bytes(b"altered-model")
    real_stat = Path.stat

    def coarse_stat(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == model:
            return verified_metadata
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", coarse_stat)
    monkeypatch.setattr(
        comfyui_module.time,
        "time_ns",
        lambda: max(verified_metadata.st_mtime_ns, verified_metadata.st_ctime_ns)
        + comfyui_module._MODEL_DIGEST_CACHE_SETTLE_NS
        + 1,
    )
    capabilities = executor.capabilities()
    assert capabilities["model_digests"] == []
    assert capabilities["execution_policy"]["models_failed"] == 1
    payload = json.dumps({"workflow": {"1": {"class_type": "SafeNode", "inputs": {}}}}).encode()
    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(_request(payload), ExecutionContext(tmp_path / "work"))
    assert raised.value.code == ErrorCode.DEPENDENCY_MISSING
    assert raised.value.details == {"reason": "model_integrity_unavailable"}


def test_comfyui_model_verification_reports_bytes_and_completion(tmp_path: Path) -> None:
    output_dir = tmp_path / "outputs"
    model_root = tmp_path / "models"
    output_dir.mkdir()
    (model_root / "diffusion_models").mkdir(parents=True)
    model = model_root / "diffusion_models/model.safetensors"
    contents = b"trusted-model"
    model.write_bytes(contents)
    digest = sha256(contents).hexdigest()
    policy = ComfyUIExecutionPolicy.from_mapping(
        {
            "version": 1,
            "allowed_node_classes": ["SafeNode"],
            "models": [
                {
                    "path": "diffusion_models/model.safetensors",
                    "sha256": f"sha256:{digest}",
                    "size": len(contents),
                }
            ],
        }
    )
    progress = []
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        output_dir,
        client=FakeComfyClient(output_dir / "result.mp4"),
        policy=policy,
        model_root=model_root,
        model_verification_progress=progress.append,
    )

    executor.capabilities()

    assert progress[0].model_index == 1
    assert progress[0].model_count == 1
    assert progress[0].file_bytes_read == 0
    assert progress[-1].path == "diffusion_models/model.safetensors"
    assert progress[-1].file_bytes_read == len(contents)
    assert progress[-1].total_bytes_read == len(contents)
    assert progress[-1].total_size == len(contents)


@pytest.mark.parametrize(
    "path",
    ["../escape.safetensors", "/absolute.safetensors", "C:\\escape.safetensors"],
)
def test_comfyui_policy_rejects_model_paths_outside_model_root(path: str) -> None:
    with pytest.raises(ComfyUIPolicyError, match="stay under the model root"):
        ComfyUIExecutionPolicy.from_mapping(
            {
                "version": 1,
                "allowed_node_classes": ["SafeNode"],
                "models": [
                    {
                        "path": path,
                        "sha256": "sha256:" + "a" * 64,
                        "size": 1,
                    }
                ],
            }
        )


def test_comfyui_policy_rejects_unsafe_maintenance_workflow_binding() -> None:
    with pytest.raises(ComfyUIPolicyError, match="maintenance workflow binding"):
        ComfyUIExecutionPolicy.from_mapping(
            {
                "version": 1,
                "allowed_node_classes": ["SafeNode"],
                "maintenance_workflows": {"vgen/minimax h3@1.0.0": "sha256:" + "a" * 64},
            }
        )


def test_comfyui_policy_file_requires_explicit_classes_and_safe_permissions(
    tmp_path: Path,
) -> None:
    policy_file = tmp_path / "comfy-policy.yaml"
    policy_file.write_text(
        """\
version: 1
allowed_node_classes:
  - LoadImage
allowed_custom_node_classes:
  - ReviewedCustomNode
max_nodes: 16
""",
        encoding="utf-8",
    )
    policy_file.chmod(0o600)

    policy = ComfyUIExecutionPolicy.load(policy_file)

    assert policy.allowed_node_classes == {"LoadImage"}
    assert policy.allowed_custom_node_classes == {"ReviewedCustomNode"}
    assert policy.max_nodes == 16

    policy_file.chmod(0o622)
    with pytest.raises(ComfyUIPolicyError, match="must not be writable"):
        ComfyUIExecutionPolicy.load(policy_file)


def test_comfyui_policy_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    policy_file = tmp_path / "comfy-policy.yaml"
    policy_file.write_text(
        """\
version: 1
allowed_node_classes: [LoadImage]
allowed_node_classes: [SaveImage]
""",
        encoding="utf-8",
    )
    policy_file.chmod(0o600)

    with pytest.raises(ComfyUIPolicyError, match="duplicate key"):
        ComfyUIExecutionPolicy.load(policy_file)
