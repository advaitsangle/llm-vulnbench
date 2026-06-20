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


class C3LLMRules(_Planned):
    id = "C3"
    label = "LLM-authored Semgrep rules (LLM improves the tool)"
    needs_model = False  # uses a model offline, not at scored-scan time
    plan = (
        "Offline: model writes/refines custom Semgrep YAML rules (validated via "
        "`semgrep --validate`); then Semgrep runs them deterministically. Author "
        "rules on a tuning split, score on the held-out split to avoid "
        "benchmark-gaming. Deterministic + reproducible at scan time."
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
