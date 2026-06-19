"""C1 — LLM + Semgrep output. The scanner-assisted (triage) condition.

This is the LLM4SA / LSAST pattern and the highest-value cell per ``claude.md``:
Semgrep runs first, and the model is shown each finding (with the surrounding code)
and asked to confirm, downgrade, or reject it, and to add anything Semgrep missed
in the same file. Grouping Semgrep findings by file keeps the model's context tight
and its judgement local to the evidence.
"""

from __future__ import annotations

from collections import defaultdict

from ..corpus import Target
from ..models import Usage
from ..scanners import run_semgrep
from ..scanners.semgrep_runner import DEFAULT_RULESET
from ..schema import Finding, Location
from .b3_llm import _read
from .base import Condition, ConditionContext, ConditionResult
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, parse_findings


class C1LLMSemgrep(Condition):
    id = "C1"
    label = "LLM + Semgrep output (scanner-assisted triage)"
    needs_model = True

    def validate(self, target: Target, ctx: ConditionContext) -> None:
        super().validate(target, ctx)
        if not target.source_path:
            raise ValueError(f"C1 needs target.source_path; {target.name} has none.")

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        ruleset = ctx.config.get("semgrep_ruleset", DEFAULT_RULESET)
        max_bytes = int(ctx.config.get("max_file_bytes", 60_000))

        semgrep = run_semgrep(target.source_path, config=ruleset, source_condition=self.id)
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in semgrep.findings:
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
                "ruleset": ruleset,
                "semgrep_version": semgrep.version,
                "semgrep_raw_findings": len(semgrep.findings),
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
