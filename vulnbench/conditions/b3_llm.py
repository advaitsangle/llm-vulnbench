"""B3 — LLM only. The unaided model reads source and reports vulnerabilities.

Scope control: the OWASP Benchmark is thousands of small files, so we iterate
per source file (each Benchmark test case is one file) up to a configurable cap,
asking the model for findings on each. Per-file findings inherit the file path, so
they resolve to Benchmark test cases for scoring without extra bookkeeping.
"""

from __future__ import annotations

import os

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, benchmark_case_of
from .base import Condition, ConditionContext, ConditionResult, Knob
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, parse_findings

#: Source extensions worth scanning; keeps the model off assets and configs.
CODE_EXTS = {".java", ".py", ".js", ".ts", ".php", ".rb", ".go"}

#: Shared by every condition that walks a source tree file-by-file (B3, A1).
SCAN_KNOBS = (
    Knob("max_files", "int", 0,
         help="cap on source files read (0 = no cap); a reproducible sorted subset"),
    Knob("max_file_bytes", "int", 60_000,
         help="truncate each file past this many bytes"),
)


class B3LLM(Condition):
    id = "B3"
    label = "LLM only (unaided)"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))

        findings: list[Finding] = []
        usage = Usage()
        scanned = 0
        truncated: list[str] = []
        scored_cases: set[str] = set()
        for path in _iter_source_files(target.source_path, max_files):
            tc = benchmark_case_of(path)
            if tc is not None:
                scored_cases.add(tc)  # in scope even if the model finds nothing in it
            code, was_truncated = _read(path, max_bytes)
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


def _iter_source_files(root: str, cap: int | None):
    # Sort both directories and files so a capped subset is the *same* subset on
    # every machine — required for reproducible (and fair) scored runs.
    count = 0
    for dirpath, dirnames, files in os.walk(root):
        dirnames.sort()
        for name in sorted(files):
            if os.path.splitext(name)[1].lower() in CODE_EXTS:
                yield os.path.join(dirpath, name)
                count += 1
                if cap and count >= cap:
                    return


def _read(path: str, max_bytes: int) -> tuple[str, bool]:
    """Read up to ``max_bytes``; return ``(text, truncated)``.

    Truncation is surfaced (not silent) so a vuln past the cap is an observable
    limitation, recorded per run rather than disappearing.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            chunk = fh.read(max_bytes + 1)
    except OSError:
        return "", False
    if len(chunk) > max_bytes:
        return chunk[:max_bytes], True
    return chunk, False
