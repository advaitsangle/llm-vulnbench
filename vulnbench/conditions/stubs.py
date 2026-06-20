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


class A1MultiAgent(_Planned):
    id = "A1"
    label = "Multi-agent roles (scan + verify)"
    needs_model = True
    plan = (
        "Scanning agent drives Semgrep/ZAP as tools; a separate verifier agent "
        "checks each finding before it is reported (role-to-role handoff). Scoped "
        "as a stretch demo on realistic apps, not a scored Benchmark sweep."
    )
