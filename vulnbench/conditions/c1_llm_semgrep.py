"""C1 — LLM + Semgrep output. The scanner-assisted (triage) condition.

This is the LLM4SA / LSAST pattern and the highest-value cell:
Semgrep runs first, and the model is shown each finding (with the surrounding code)
and asked to confirm, downgrade, or reject it, and to add anything Semgrep missed
in the same file. Grouping Semgrep findings by file keeps the model's context tight
and its judgement local to the evidence.

The two phases (Semgrep scan, then model triage) are split via the
:class:`TriageCondition` base so they can run separately — see ``scan_out`` /
``scan_in`` there. For C1 the scan is cheap (Semgrep is a CLI, no Docker), so the
split is mostly about reusing one scan across several models; the RAM win matters
more for C2's Dockerized DAST scan.
"""

from __future__ import annotations

from collections import defaultdict

from ..corpus import Target, TargetKind
from ..models import Usage
from ..scanners import run_semgrep
from ..schema import Finding, Location
from ..scoring import benchmark_cases_in_tree
from .b1_semgrep import B1Semgrep
from .b3_llm import _read
from .base import ConditionContext, ConditionResult, Knob, TriageCondition
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, parse_findings


class C1LLMSemgrep(TriageCondition):
    id = "C1"
    label = "LLM + Semgrep output (scanner-assisted triage)"
    needs_model = True
    # Triage-only (scan_in) reads the source files referenced by the loaded findings,
    # not target.source_path; TriageCondition.validate relaxes this requirement there.
    needs_source = True
    tools = ("semgrep",)
    knobs = (
        B1Semgrep.knob("semgrep_ruleset"),  # C1's scan phase *is* B1's scan
        Knob("max_file_bytes", "int", 60_000,
             help="truncate each file past this many bytes when showing it to the model"),
    )

    def scope(self, target: Target, ctx: ConditionContext) -> set[str] | None:
        # Semgrep scanned the whole source tree; the in-scope Benchmark cases are
        # the files under it. Triage-only (scan_in) can't know what the upstream
        # scan covered, so it falls back to full-GT scoring.
        if self.cfg(ctx, "scan_in") or target.kind is not TargetKind.BENCHMARK:
            return None
        if not target.source_path:
            return None
        return benchmark_cases_in_tree(target.source_path) or None

    def scan(self, target: Target, ctx: ConditionContext) -> tuple[list[Finding], dict]:
        ruleset = self.cfg(ctx, "semgrep_ruleset")
        semgrep = run_semgrep(target.source_path, config=ruleset, source_condition=self.id)
        trace = {
            "ruleset": ruleset,
            "semgrep_version": semgrep.version,
            "semgrep_raw_findings": len(semgrep.findings),
        }
        return semgrep.findings, trace

    def triage(
        self, scanner_findings: list[Finding], target: Target, ctx: ConditionContext
    ) -> ConditionResult:
        assert ctx.model is not None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))

        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in scanner_findings:
            by_file[f.location.file or ""].append(f)

        findings: list[Finding] = []
        usage = Usage()
        truncated = 0
        for path, raw in by_file.items():
            code, was_truncated = _read(path, max_bytes) if path else ("", False)
            truncated += int(was_truncated)
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _triage_prompt(path, code, raw)},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage
            for f in parse_findings(completion.text, self.id):
                if f.location.file is None and path:
                    f.location = Location.source(file=path, line=f.location.line)
                findings.append(f)

        return ConditionResult(
            findings=findings,
            usage=usage,
            trace={
                "model": ctx.model.name,
                "files_reviewed": len(by_file),
                "truncated_files": truncated,
            },
        )


def _triage_prompt(path: str, code: str, raw: list[Finding]) -> str:
    listed = "\n".join(
        f"- CWE-{f.vuln_class} at line {f.location.line} "
        f"(rule {f.rule_id}): {f.message or ''}"
        for f in raw
    )
    return (
        "Semgrep flagged the following potential vulnerabilities in this file. "
        "For each, decide whether it is a real vulnerability (confirmed), "
        "plausible but unverified (candidate), or a false positive "
        "(not_supported). Also report any genuine vulnerability in the same file "
        "that Semgrep missed.\n\n"
        f"File: {path}\n\nSemgrep findings:\n{listed}\n\n"
        f"Source:\n```\n{code}\n```\n\n{OUTPUT_CONTRACT}"
    )
