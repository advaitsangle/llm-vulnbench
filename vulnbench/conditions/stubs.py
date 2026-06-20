"""Registered-but-unbuilt conditions.

These are wired into the registry so the matrix, CLI ``--list``, and reports all
know they exist, but they raise an actionable error if run. Each docstring records
the intended design from ``claude.md`` so filling it in is a localized task.
"""

from __future__ import annotations

from ..corpus import Target
from .base import Condition, ConditionContext, ConditionResult


class _Planned(Condition):
    """Base for not-yet-implemented conditions."""

    plan: str = ""

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        raise NotImplementedError(
            f"Condition {self.id} ({self.label}) is not implemented yet.\n"
            f"Plan: {self.plan}"
        )


class A2SourceToSink(_Planned):
    id = "A2"
    label = "Source-to-sink finder (pure-LLM taint walk)"
    needs_model = True
    plan = (
        "Pure-LLM source-to-sink hunter: from entry points (routes/controllers) "
        "the model follows untrusted data across files toward sinks, reading only "
        "along tainted paths instead of every file. Scoped as a demo on a realistic "
        "app (OWASP Juice Shop), not a scored Benchmark sweep."
    )
