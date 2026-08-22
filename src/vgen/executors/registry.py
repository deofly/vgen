"""Executor discovery/selection isolated from the Worker Core."""

from __future__ import annotations

from collections.abc import Iterator

from vgen.protocol import ErrorCode

from .base import Executor, ExecutorDescriptor, ExecutorFailure, RetryAction


class ExecutorRegistry:
    def __init__(self, *executors: Executor) -> None:
        self._executors: dict[str, Executor] = {}
        for executor in executors:
            self.register(executor)

    def register(self, executor: Executor) -> None:
        if not isinstance(executor, Executor):
            raise TypeError("executor does not implement the Executor contract")
        descriptor = executor.descriptor()
        if descriptor.executor_type in self._executors:
            raise ValueError(f"executor already registered: {descriptor.executor_type}")
        self._executors[descriptor.executor_type] = executor

    def get(self, executor_type: str) -> Executor:
        try:
            return self._executors[executor_type]
        except KeyError as exc:
            raise ExecutorFailure(
                ErrorCode.EXECUTOR_UNAVAILABLE,
                "EXECUTOR_UNAVAILABLE",
                "The requested executor is not installed on this worker.",
                retry_action=RetryAction.ANOTHER_WORKER,
                details={"executor_type": executor_type},
            ) from exc

    def descriptors(self) -> tuple[ExecutorDescriptor, ...]:
        return tuple(executor.descriptor() for executor in self._executors.values())

    def __iter__(self) -> Iterator[Executor]:
        return iter(self._executors.values())
