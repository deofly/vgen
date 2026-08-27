"""Bounded task-failure diagnostics safe to cross an untrusted Worker boundary."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from .errors import ErrorCode

# These values are protocol vocabulary, not free-form strings. A Worker sees
# decrypted task inputs and therefore must not be allowed to persist arbitrary
# text through an apparently harmless diagnostic field.
_UNSUPPORTED_PAYLOAD_REASONS = frozenset(
    {
        "cyclic_graph",
        "dangling_node_connection",
        "duplicate_input_binding",
        "empty_graph",
        "graph_depth_limit",
        "graph_edge_limit",
        "graph_mapping_limit",
        "graph_node_limit",
        "graph_sequence_limit",
        "graph_value_depth_limit",
        "graph_value_size_limit",
        "input_binding_limit",
        "input_binding_target_not_allowed",
        "invalid_input_binding",
        "invalid_input_binding_field",
        "invalid_input_field",
        "invalid_nested_field",
        "invalid_node_class",
        "invalid_node_connection",
        "invalid_node_identifier",
        "invalid_node_inputs",
        "invalid_node_metadata",
        "invalid_numeric_value",
        "node_class_not_allowed",
        "node_input_limit",
        "operation_not_allowed_by_workflow",
        "payload_size_limit",
        "unbound_load_image",
        "unexpected_node_structure",
        "unsafe_local_path",
        "unsupported_graph_value",
        "workflow_bindings_mismatch",
        "workflow_graph_mismatch",
        "workflow_mapping_invalid",
        "workflow_not_allowed",
        "workflow_operation_mismatch",
        "workflow_parameters_invalid",
        "workflow_parameters_not_canonical",
        "workflow_parameters_required",
    }
)

_DEPENDENCY_MISSING_REASONS = frozenset(
    {
        "history_missing",
        "input_upload_rejected",
        "invalid_input_upload_response",
        "invalid_prompt_response",
        "local_execution_failed",
        "model_integrity_unavailable",
        "model_load_incompatible",
        "model_not_found",
        "no_output",
        "node_class_missing",
        "node_runtime_error",
        "node_validation_failed",
        "python_dependency_missing",
        "tensor_shape_mismatch",
        "workflow_rejected",
    }
)

_FAILURE_REASONS_BY_CODE = {
    ErrorCode.UNSUPPORTED_PAYLOAD: _UNSUPPORTED_PAYLOAD_REASONS,
    ErrorCode.EXECUTOR_UNAVAILABLE: frozenset(
        {"output_path_outside_root", "policy_required"}
    ),
    ErrorCode.DEPENDENCY_MISSING: _DEPENDENCY_MISSING_REASONS,
    ErrorCode.GPU_OUT_OF_MEMORY: frozenset(
        {"gpu_out_of_memory", "insufficient_vram"}
    ),
    ErrorCode.SYSTEM_OUT_OF_MEMORY: frozenset(
        {"insufficient_ram", "system_out_of_memory"}
    ),
}

SAFE_TASK_FAILURE_REASONS = frozenset(
    reason for reasons in _FAILURE_REASONS_BY_CODE.values() for reason in reasons
) | frozenset(code.name.lower() for code in ErrorCode)
SAFE_TASK_FAILURE_PHASES = frozenset({"preparing", "executing", "uploading"})
SAFE_TASK_FAILURE_COMPONENTS = frozenset(
    {"decoder", "encoder", "model_loader", "output", "sampler"}
)
SAFE_TASK_PROGRESS_STAGES = frozenset(
    {
        "downloading_inputs",
        "preparing",
        "processing",
        "queued",
        "resuming_output_upload",
        "sampled",
        "sampling",
        "uploading_outputs",
    }
)


def canonical_task_failure_details(details: Mapping[str, Any] | None) -> dict[str, str]:
    """Return only fixed protocol values.

    This vocabulary-only helper is intentionally insufficient at a trust
    boundary: callers that know the terminal error code must additionally use
    :func:`canonical_task_failure_details_for_code` so a valid reason cannot be
    paired with an unrelated outcome.
    """

    if not isinstance(details, Mapping):
        return {}
    canonical: dict[str, str] = {}
    reason = details.get("reason")
    if isinstance(reason, str) and reason in SAFE_TASK_FAILURE_REASONS:
        canonical["reason"] = reason
    phase = details.get("phase")
    if isinstance(phase, str) and phase in SAFE_TASK_FAILURE_PHASES:
        canonical["phase"] = phase
    component = details.get("component")
    if isinstance(component, str) and component in SAFE_TASK_FAILURE_COMPONENTS:
        canonical["component"] = component
    return canonical


def canonical_task_failure_details_for_code(
    details: Mapping[str, Any] | None,
    failure_code: ErrorCode | int | None,
    *,
    terminal_state: str | None = None,
) -> dict[str, str]:
    """Bind fixed diagnostics to one registered terminal outcome.

    Successful and cancelled attempts never retain failure diagnostics. Unknown
    codes are treated as untrusted rather than being coerced to a nearby code.
    """

    if terminal_state in {"succeeded", "cancelled"} or failure_code is None:
        return {}
    try:
        code = ErrorCode(failure_code)
    except (TypeError, ValueError):
        return {}
    if code is ErrorCode.EXECUTION_CANCELLED:
        return {}

    candidate = canonical_task_failure_details(details)
    canonical: dict[str, str] = {}
    reason = candidate.get("reason")
    allowed_reasons = _FAILURE_REASONS_BY_CODE.get(code, frozenset()) | frozenset(
        {code.name.lower()}
    )
    if reason in allowed_reasons:
        canonical["reason"] = reason

    # A phase describes the Worker's unexpected internal boundary, not a
    # provider response or consumer payload error.
    if code is ErrorCode.INTERNAL_ERROR and "phase" in candidate:
        canonical["phase"] = candidate["phase"]

    # Components are deliberately limited to the fixed ComfyUI provider-side
    # classifications. They are not accepted for consumer payload failures.
    if code in {
        ErrorCode.EXECUTOR_UNAVAILABLE,
        ErrorCode.DEPENDENCY_MISSING,
        ErrorCode.EXECUTION_TIMEOUT,
        ErrorCode.GPU_OUT_OF_MEMORY,
        ErrorCode.SYSTEM_OUT_OF_MEMORY,
    } and "component" in candidate:
        canonical["component"] = candidate["component"]
    return canonical


def canonical_task_progress(progress: Mapping[str, Any] | None) -> dict[str, float | str] | None:
    """Bound progress to fixed stages and percent precision.

    Executor plugins and ComfyUI nodes see decrypted inputs. Neither arbitrary
    stage text nor full-precision floats may therefore cross the Worker trust
    boundary into persistent task metadata.
    """

    if not isinstance(progress, Mapping):
        return None
    fraction = progress.get("fraction")
    stage = progress.get("stage")
    if (
        not isinstance(fraction, (int, float))
        or isinstance(fraction, bool)
        or not math.isfinite(float(fraction))
        or not 0 <= float(fraction) <= 1
        or not isinstance(stage, str)
    ):
        return None
    return {
        "fraction": round(float(fraction), 2),
        "stage": stage if stage in SAFE_TASK_PROGRESS_STAGES else "processing",
    }


__all__ = [
    "SAFE_TASK_FAILURE_COMPONENTS",
    "SAFE_TASK_FAILURE_PHASES",
    "SAFE_TASK_FAILURE_REASONS",
    "SAFE_TASK_PROGRESS_STAGES",
    "canonical_task_failure_details",
    "canonical_task_failure_details_for_code",
    "canonical_task_progress",
]
