"""B3 — LLM only. The unaided model reads source and reports vulnerabilities.

Scope control: the OWASP Benchmark is thousands of small files, so we iterate
per source file (each Benchmark test case is one file) up to a configurable cap,
asking the model for findings on each. Per-file findings inherit the file path, so
they resolve to Benchmark test cases for scoring without extra bookkeeping.
"""

from __future__ import annotations

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, benchmark_case_of
from .base import Condition, ConditionContext, ConditionResult
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, parse_findings
from .source_files import (
    SAMPLE_KNOBS,
    SCAN_KNOBS,
    iter_source_files,
    read_capped,
    sampled_paths_for,
)


class B3LLM(Condition):
    id = "B3"
    label = "LLM only (unaided)"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + SAMPLE_KNOBS

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))
        # --sample overrides max_files: the smoke slice *is* the file set.
        paths = sampled_paths_for(self, ctx, target.source_path)
        if paths is None:
            paths = iter_source_files(target.source_path, max_files)

        findings: list[Finding] = []
        usage = Usage()
        scanned = 0
        truncated: list[str] = []
        scored_cases: set[str] = set()
        for path in paths:
            tc = benchmark_case_of(path)
            if tc is not None:
                scored_cases.add(tc)  # in scope even if the model finds nothing in it
            code, was_truncated = read_capped(path, max_bytes)
            if not code:
                continue
            if was_truncated:
                truncated.append(path)
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_prompt(path, code)},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage
            for f in parse_findings(completion.text, self.id):
                # Pin the location to the file we actually scanned.
                if f.location.file is None:
                    f.location = Location.source(file=path, line=f.location.line)
                findings.append(f)
            scanned += 1

        return ConditionResult(
            findings=findings,
            usage=usage,
            trace={
                "files_scanned": scanned,
                "model": ctx.model.name,
                "truncated_files": len(truncated),
                "max_file_bytes": max_bytes,
            },
            # Score only over what we actually looked at (respects max_files).
            scored_cases=scored_cases or None,
        )


def _user_prompt(path: str, code: str) -> str:
    return (
        f"Analyze this source file for security vulnerabilities.\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{OUTPUT_CONTRACT}"
    )
