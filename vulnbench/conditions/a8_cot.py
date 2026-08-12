"""A8 — Chain-of-thought. The model must reason step by step before any verdict.

Prompt-level augmentation: B3 asks for a verdict directly; A8 requires a top-level
``analysis`` array — entry points, sinks, flows, mitigations, conclusion — emitted
before the findings. Everything else is B3's, so any difference in the scorecard is
attributable to the forced reasoning alone.

Compliance is measured, not assumed: ``cot_followed_count`` / ``cot_followed_frac``
record how often the model actually produced an analysis array, so a null result can
be read as "reasoning did not help" rather than "the model ignored the instruction".

Deliberately has no few-shot knob. A8 and :mod:`a7_fewshot` are separate conditions
that are never configured together — combining them would pair a prompt demanding an
analysis array with example replies that omit one, teaching the model that ignoring
the instruction is correct, and the compliance figure above would measure the prompt
rather than the model.
"""

from __future__ import annotations

from typing import Any

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, benchmark_case_of
from .base import Condition, ConditionContext, ConditionResult
from .llm_common import OUTPUT_CONTRACT, SYSTEM_PROMPT, _extract_json_object, parse_findings
from .source_files import (
    SAMPLE_KNOBS,
    SCAN_KNOBS,
    iter_source_files,
    read_capped,
    sampled_paths_for,
)

COT_PREFIX = (
    "Before listing findings, emit a top-level \"analysis\" array of 3–6 short "
    "steps. Each step is a plain string. Work through:\n"
    "  1. Entry points — which inputs are untrusted (HTTP params, headers, "
    "cookies, request bodies, env vars)?\n"
    "  2. Sinks — which dangerous operations does this code invoke (SQL, OS "
    "command, file path, HTML output, reflection, deserialization)?\n"
    "  3. Data flows — does any untrusted input reach a sink without "
    "sufficient sanitization or parameterization?\n"
    "  4. Mitigations — are there validators, allow-lists, prepared statements, "
    "or other controls that break the flow?\n"
    "  5. Conclusion — what verdicts follow?\n\n"
    "The full response shape (analysis comes first):\n"
    "{\n"
    "  \"analysis\": [\"<step 1>\", \"<step 2>\", ...],\n"
    "  \"findings\": [ ... ]\n"
    "}\n\n"
    "If you find nothing, return {\"analysis\": [\"No untrusted inputs reach "
    "dangerous sinks.\"], \"findings\": []}.\n\n"
)

COT_SYSTEM_SUFFIX = (
    " Before reporting findings, reason step by step: identify entry points, "
    "trace data flows to sinks, check mitigations, then commit to verdicts."
)


class A8ChainOfThought(Condition):
    id = "A8"
    label = "Chain-of-thought (reason before verdict)"
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
        cot_followed = 0

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
                {"role": "system", "content": SYSTEM_PROMPT + COT_SYSTEM_SUFFIX},
                {"role": "user", "content": _user_prompt_cot(path, code)},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage

            raw_findings, analysis = self._parse_reply(completion.text)
            if analysis is not None:
                cot_followed += 1

            for f in raw_findings:
                # Pin the location to the file we actually scanned.
                if f.location.file is None:
                    f.location = Location.source(file=path, line=f.location.line)
                # Attach reasoning to extra so findings.json records it.
                if analysis is not None:
                    f.extra = {**f.extra, "cot_analysis": analysis}
                findings.append(f)
            scanned += 1

        trace: dict[str, Any] = {
            "files_scanned": scanned,
            "model": ctx.model.name,
            "truncated_files": len(truncated),
            "max_file_bytes": max_bytes,
            "cot_followed_count": cot_followed,
            "cot_followed_frac": round(cot_followed / scanned, 3) if scanned else 0.0,
        }
        return ConditionResult(
            findings=findings,
            usage=usage,
            trace=trace,
            scored_cases=scored_cases or None,
        )

    def _parse_reply(self, text: str) -> tuple[list[Finding], list[str] | None]:
        """Findings plus the analysis array, or ``None`` if the model skipped it."""
        obj = _extract_json_object(text)
        analysis: list[str] | None = None
        if obj is not None:
            raw = obj.get("analysis")
            if isinstance(raw, list) and raw:
                steps = [s for s in raw if isinstance(s, str)]
                if steps:
                    analysis = steps
        return parse_findings(text, self.id), analysis


def _user_prompt_cot(path: str, code: str) -> str:
    return (
        f"Analyze this source file for security vulnerabilities.\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{COT_PREFIX}{OUTPUT_CONTRACT}"
    )
