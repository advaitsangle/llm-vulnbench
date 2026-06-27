"""The model-backend contract.

Every condition that uses an LLM talks to a :class:`ModelBackend` and never to a
concrete provider. That single seam is what makes "local Qwen vs frontier Claude"
a swappable factor rather than a code fork. Backends report token usage and
latency so the engineering metrics
(cost, wall-clock) come for free.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolSpec:
    """A tool the model may call (used by C-conditions and the A1 agent loop)."""

    name: str
    description: str
    # JSON-Schema for the tool's arguments, provider-agnostic.
    parameters: dict[str, Any]


@dataclass
class Usage:
    """Token accounting for one or more completions; additive across a run."""

    input_tokens: int = 0
    output_tokens: int = 0
    # Wall-clock seconds spent in the backend (latency is an engineering metric).
    seconds: float = 0.0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.seconds + other.seconds,
        )


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    call_id: str | None = None


@dataclass
class Completion:
    """A single model response.

    ``text`` is the assistant message; ``tool_calls`` is non-empty when the model
    asked to invoke a tool (the harness runs it and calls ``complete`` again with
    the result appended to ``messages``).
    """

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    raw: Any = None


class ModelBackend(ABC):
    """One LLM, addressed uniformly.

    Implementations override :meth:`_complete`. ``complete`` wraps it to stamp
    latency onto usage so every caller measures it the same way.
    """

    #: Identifier used in scorecards, e.g. ``local:qwen2.5-coder:14b``.
    name: str = "unknown"
    #: Low temperature by default: webllm measured 0.7 -> 31% fabrication,
    #: 0.1 -> 12%. Detection wants determinism, not creativity.
    temperature: float = 0.1

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec] | None = None,
        **kwargs: Any,
    ) -> Completion:
        start = time.perf_counter()
        result = self._complete(messages, tools=tools, **kwargs)
        result.usage.seconds += time.perf_counter() - start
        return result

    @abstractmethod
    def _complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec] | None = None,
        **kwargs: Any,
    ) -> Completion: ...
