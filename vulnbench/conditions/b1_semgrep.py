"""B1 — Semgrep only. The SAST baseline."""

from __future__ import annotations

from ..corpus import Target, TargetKind
from ..scanners import run_semgrep
from ..scanners.semgrep_runner import DEFAULT_RULESET
from ..scoring import benchmark_cases_in_tree, benchmark_cases_of
from .base import Condition, ConditionContext, ConditionResult, Knob
from .source_files import SAMPLE_KNOBS, sampled_paths_for


class B1Semgrep(Condition):
    id = "B1"
    label = "Semgrep only (SAST baseline)"
    needs_model = False
    needs_source = True
    tools = ("semgrep",)
    knobs = (
        Knob("semgrep_ruleset", "str", DEFAULT_RULESET,
             help="Semgrep config to scan with (registry id like p/java, or a rules file)"),
    ) + SAMPLE_KNOBS

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        ruleset = self.cfg(ctx, "semgrep_ruleset")
        # --sample: scan only the smoke-test slice instead of the whole tree.
        sampled = sampled_paths_for(self, ctx, target.source_path)
        result = run_semgrep(
            sampled if sampled is not None else target.source_path,
            config=ruleset, source_condition=self.id,
        )
        # The in-scope cases are exactly the Benchmark files Semgrep was shown —
        # the sampled slice, or every file under the tree — so scoring stays honest.
        scored_cases = None
        if target.kind is TargetKind.BENCHMARK:
            in_scope = (benchmark_cases_of(sampled) if sampled is not None
                        else benchmark_cases_in_tree(target.source_path))
            scored_cases = in_scope or None
        return ConditionResult(
            findings=result.findings,
            trace={
                "command": result.command,
                "ruleset": ruleset,
                "semgrep_version": result.version,
                **({"sampled_files": len(sampled)} if sampled is not None else {}),
            },
            scored_cases=scored_cases,
        )
