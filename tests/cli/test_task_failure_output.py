from __future__ import annotations

from vgen.cli.main import _task_terminal_error
from vgen.protocol.errors import ErrorCode


def test_task_terminal_error_renders_only_bounded_diagnostic_codes() -> None:
    error = _task_terminal_error(
        {
            "id": "tsk_example",
            "state": "failed",
            "attempts": [
                {
                    "failure_code": int(ErrorCode.DEPENDENCY_MISSING),
                    "safe_failure_details": {
                        "reason": "tensor_shape_mismatch",
                        "node_id": "405:344",
                        "node_type": "SamplerCustomAdvanced",
                        "component": "sampler",
                        "exception_message": "secret prompt and C:/private/model.gguf",
                        "phase": "C:/Users/private/model.gguf",
                        "error_type": "U0VDUkVUX1BST01QVA",
                    },
                }
            ],
        }
    )

    rendered = str(error)
    assert error.code == int(ErrorCode.DEPENDENCY_MISSING)
    assert error.name == "DEPENDENCY_MISSING"
    assert "task_id=tsk_example" in rendered
    assert "reason=tensor_shape_mismatch" in rendered
    assert "component=sampler" in rendered
    assert "node_id" not in rendered
    assert "node_type" not in rendered
    assert "secret prompt" not in rendered
    assert "private/model" not in rendered
    assert "U0VDUkVUX1BST01QVA" not in rendered


def test_cancelled_task_without_attempt_failure_uses_execution_cancelled() -> None:
    error = _task_terminal_error(
        {"id": "tsk_cancelled", "state": "cancelled", "attempts": []}
    )

    assert error.code == int(ErrorCode.EXECUTION_CANCELLED)
    assert error.name == "EXECUTION_CANCELLED"


def test_system_oom_keeps_only_code_bound_details_and_retries_another_worker() -> None:
    error = _task_terminal_error(
        {
            "id": "tsk_systemoom",
            "state": "failed",
            "attempts": [
                {
                    "state": "failed",
                    "failure_code": int(ErrorCode.SYSTEM_OUT_OF_MEMORY),
                    "safe_failure_details": {
                        "reason": "system_out_of_memory",
                        "component": "sampler",
                        "phase": "executing",
                        "status_code": 507,
                        "prompt": "private prompt",
                    },
                }
            ],
        }
    )

    assert error.code == int(ErrorCode.SYSTEM_OUT_OF_MEMORY)
    assert error.name == "SYSTEM_OUT_OF_MEMORY"
    assert error.retry_action == "another_worker"
    assert error.details == {
        "reason": "system_out_of_memory",
        "component": "sampler",
    }
    assert "private prompt" not in str(error)
    assert "507" not in str(error)
