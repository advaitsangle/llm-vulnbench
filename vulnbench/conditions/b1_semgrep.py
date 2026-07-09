"""B1 — Semgrep only. The SAST baseline."""

from __future__ import annotations

from ..corpus import Target, TargetKind
from ..scanners import run_semgrep
from ..scanners.semgrep_runner import DEFAULT_RULESET
from ..scoring import benchmark_cases_in_tree
from .base import Condition, ConditionContext, ConditionResult, Knob


class B1Semgrep(Condition):
    id = "B1"
    label = "Semgrep only (SAST baseline)"
    needs_model = False
    needs_source = True
    knobs = (
        Knob("semgrep_ruleset", "str", DEFAULT_RULESET,
             help="Semgrep config to scan with (registry id like p/java, or a rules file)"),
    )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        ruleset = self.cfg(ctx, "semgrep_ruleset")
        result = run_semgrep(target.source_path, config=ruleset, source_condition=self.id)
        # Semgrep scans the whole tree, so the in-scope cases are exactly the
        # Benchmark files present under it — honest scoring for a sliced --source.
        scored_cases = (
            benchmark_cases_in_tree(target.source_path) or None
            if target.kind is TargetKind.BENCHMARK
            else None
        )
        return ConditionResult(
            findings=result.findings,
            trace={
                "command": result.command,
                "ruleset": ruleset,
                "semgrep_version": result.version,
            },
            scored_cases=scored_cases,
        )
