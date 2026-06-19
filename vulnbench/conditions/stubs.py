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


class B2Zap(_Planned):
    id = "B2"
    label = "OWASP ZAP only (DAST baseline)"
    needs_model = False
    plan = (
        "Drive ZAP in daemon mode via its REST API (spider -> active scan -> "
        "alerts). Map each alert's CWE + URL/method/param to a Finding with an "
        "ENDPOINT location. Requires target.base_url. ZAP scorecard generator in "
        "BenchmarkUtils confirms Benchmark compatibility."
    )


class C2LLMZap(_Planned):
    id = "C2"
    label = "LLM + ZAP output (scanner-assisted triage, DAST)"
    needs_model = True
    plan = (
        "Mirror C1 on the DAST side: run B2's ZAP scan, group alerts by endpoint, "
        "show each to the model with request/response evidence, ask for "
        "confirm/candidate/not_supported. Reuses llm_common parsing."
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
