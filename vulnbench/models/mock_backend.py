"""Offline, deterministic backend for tests and a fresh checkout.

The ``mock`` backend lets the whole pipeline run without a model server, which is
how the test suite and a fresh checkout exercise the LLM conditions.
"""

from __future__ import annotations

from .base import Completion, ModelBackend, Usage


class MockBackend(ModelBackend):
    """Offline, deterministic backend. Echoes a canned, schema-valid reply.

    It returns a single ``not_supported`` verdict so LLM conditions produce
    parseable output end-to-end without a live model. Override ``scripted`` to
    drive specific test scenarios.
    """

    def __init__(self, scripted: str | None = None) -> None:
        self.name = "mock"
        self.scripted = scripted or '{"findings": []}'

    def _complete(self, messages, tools=None, **kwargs) -> Completion:  # noqa: ANN001
        return Completion(text=self.scripted, usage=Usage(input_tokens=0, output_tokens=0))
