"""Execution engine contracts.

Executor-specific modules are intentionally not imported here so installing the
core package does not pull in ComfyUI, Diffusers, or SGLang dependencies.
"""

from .base import (
    ExecutionArtifact,
    ExecutionCancelled,
    ExecutionContext,
    ExecutionInput,
    ExecutionRequest,
    ExecutionResult,
    Executor,
    ExecutorDescriptor,
    ExecutorFailure,
    ExecutorHealth,
    ProgressEvent,
    RetryAction,
    UsageMetrics,
)
from .registry import ExecutorRegistry

__all__ = [
    "ExecutionArtifact",
    "ExecutionCancelled",
    "ExecutionContext",
    "ExecutionInput",
    "ExecutionRequest",
    "ExecutionResult",
    "Executor",
    "ExecutorDescriptor",
    "ExecutorFailure",
    "ExecutorHealth",
    "ExecutorRegistry",
    "ProgressEvent",
    "RetryAction",
    "UsageMetrics",
]
