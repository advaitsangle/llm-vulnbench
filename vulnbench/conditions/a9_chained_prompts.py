"""A9 — Three chained prompts over each source file.

The same model independently summarizes the code, identifies concrete
vulnerability candidates, and verifies only those candidates. Parsed JSON is
normalized between stages so model prose never becomes the next stage's input.
"""

from __future__ import annotations

import hashlib
import json
import re

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, Verdict, benchmark_case_of
from .base import Condition, ConditionContext, ConditionResult
from .llm_common import (
    OUTPUT_CONTRACT,
    SCORED_CWES,
    SYSTEM_PROMPT,
    _cwe_id,
    _extract_json_object,
    _int_or_none,
    parse_findings,
)
from .source_files import (
    SAMPLE_KNOBS,
    SCAN_KNOBS,
    iter_source_files,
    read_capped,
    sampled_paths_for,
)

_SCORED_IDS = frozenset(int(value) for value in re.findall(r"\d+", SCORED_CWES))

SUMMARY_SYSTEM = (
    "You are a precise code analyst. Summarize only security-relevant facts that "
    "are present in the source code. Do not decide whether a vulnerability exists."
)

SUMMARY_CONTRACT = """\
Respond with ONLY a JSON object of this exact shape (no markdown, no prose):
{
  "summary": "<concise description of the file's behavior>",
  "untrusted_inputs": ["<input visible in the code>"],
  "sensitive_operations": ["<security-sensitive operation visible in the code>"],
  "data_flows": ["<relevant source-to-operation flow>"],
  "mitigations": ["<validation, encoding, parameterization, or other defense>"]
}
Use an empty array when a category has no code-grounded entries."""

SUMMARY_TASK = "Summarize this source file without making a vulnerability verdict."

CANDIDATE_SYSTEM = (
    "You are a security analyst identifying areas that require verification. Use "
    "the supplied code and normalized summary to report concrete potential "
    "vulnerabilities, not final verdicts. Do not invent data flows."
)

CANDIDATE_CONTRACT = """\
Classify every candidate using ONLY a CWE id from this MITRE CWE Top 25 list:
{top25}

Respond with ONLY a JSON object of this exact shape (no markdown, no prose):
{{
  "candidates": [
    {{
      "cwe": <integer CWE id from the list above>,
      "line": <integer line number, or null>,
      "source": "<untrusted source>",
      "sink": "<dangerous sink>",
      "suspected_flow": "<how source may reach sink>",
      "reason": "<why this requires verification>",
      "mitigation_to_verify": "<possible defense to check, or null>"
    }}
  ]
}}
If there are no concrete candidates, return {{"candidates": []}}."""

CANDIDATE_TASK = "Identify concrete potentially vulnerable areas for a later verifier."

VERIFY_SYSTEM = (
    SYSTEM_PROMPT
    + " You are the final skeptical verifier in a chained analysis. Analyze only "
    "the supplied candidates. Do not introduce a CWE that is absent from them."
)

VERIFY_TASK = (
    "Verify the supplied candidates against the original code. Reject candidates "
    "whose flow is absent, sanitized, or unreachable. Do not report new candidates."
)

FALLBACK_VERIFY_SYSTEM = (
    SYSTEM_PROMPT
    + " The candidate-identification response was malformed. Perform an independent "
    "full security analysis of the original code so malformed output is not mistaken "
    "for a safe file."
)

FALLBACK_VERIFY_TASK = (
    "Candidate extraction failed because the stage-2 response was malformed. "
    "Independently analyze the original source for security vulnerabilities."
)

PROMPT_VERSION = "a9-chain-v1"

PROMPT_HASHES = {
    "summary": hashlib.sha256(
        (SUMMARY_SYSTEM + SUMMARY_TASK + SUMMARY_CONTRACT).encode()
    ).hexdigest(),
    "candidates": hashlib.sha256(
        (
            CANDIDATE_SYSTEM
            + CANDIDATE_TASK
            + CANDIDATE_CONTRACT.format(top25=SCORED_CWES)
        ).encode()
    ).hexdigest(),
    "verify": hashlib.sha256(
        (VERIFY_SYSTEM + VERIFY_TASK + OUTPUT_CONTRACT).encode()
    ).hexdigest(),
    "fallback_verify": hashlib.sha256(
        (FALLBACK_VERIFY_SYSTEM + FALLBACK_VERIFY_TASK + OUTPUT_CONTRACT).encode()
    ).hexdigest(),
}

_SUMMARY_UNAVAILABLE = {
    "summary": "Summary unavailable because the stage-1 response was malformed.",
    "untrusted_inputs": [],
    "sensitive_operations": [],
    "data_flows": [],
    "mitigations": [],
}


class A9ChainedPrompts(Condition):
    id = "A9"
    label = "Chained prompts, Top-25 CWE hunt (summarize/flag/verify)"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + SAMPLE_KNOBS

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))
        sampled = sampled_paths_for(self, ctx, target.source_path)
        paths = sampled if sampled is not None else list(
            iter_source_files(target.source_path, max_files)
        )

        findings: list[Finding] = []
        usage = Usage()
        scored_cases = {tc for path in paths if (tc := benchmark_case_of(path)) is not None}
        files_scanned = 0
        files_without_candidates = 0
        final_calls = 0
        truncated_files = 0
        summary_parse_failures = 0
        candidate_parse_failures = 0
        final_parse_failures = 0
        invalid_candidates = 0
        total_candidates = 0
        model_calls = 0
        not_supported_rejected = 0
        unexpected_findings_dropped = 0

        for path in paths:
            code, truncated = read_capped(path, max_bytes)
            if not code:
                continue
            files_scanned += 1
            truncated_files += int(truncated)

            summary_completion = ctx.model.complete(
                [
                    {"role": "system", "content": SUMMARY_SYSTEM},
                    {"role": "user", "content": _summary_prompt(path, code)},
                ]
            )
            model_calls += 1
            usage = usage + summary_completion.usage
            summary, summary_valid = _parse_summary(summary_completion.text)
            if not summary_valid:
                summary_parse_failures += 1

            candidate_completion = ctx.model.complete(
                [
                    {"role": "system", "content": CANDIDATE_SYSTEM},
                    {
                        "role": "user",
                        "content": _candidate_prompt(path, code, summary),
                    },
                ]
            )
            model_calls += 1
            usage = usage + candidate_completion.usage
            candidates, candidates_valid, rejected = _parse_candidates(
                candidate_completion.text
            )
            invalid_candidates += rejected
            total_candidates += len(candidates)
            if candidates_valid and not candidates:
                files_without_candidates += 1
                continue
            if not candidates_valid:
                candidate_parse_failures += 1

            final_calls += 1
            if candidates_valid:
                final_messages = [
                    {"role": "system", "content": VERIFY_SYSTEM},
                    {
                        "role": "user",
                        "content": _verify_prompt(path, code, summary, candidates),
                    },
                ]
            else:
                final_messages = [
                    {"role": "system", "content": FALLBACK_VERIFY_SYSTEM},
                    {
                        "role": "user",
                        "content": _fallback_verify_prompt(path, code, summary),
                    },
                ]
            final_completion = ctx.model.complete(final_messages)
            model_calls += 1
            usage = usage + final_completion.usage
            final_findings, final_valid = _parse_final(final_completion.text, self.id)
            if not final_valid:
                final_parse_failures += 1
                continue
            allowed_cwes = {candidate["cwe"] for candidate in candidates}
            for finding in final_findings:
                if finding.verdict is Verdict.NOT_SUPPORTED:
                    not_supported_rejected += 1
                    continue
                if candidates_valid and finding.vuln_class not in allowed_cwes:
                    unexpected_findings_dropped += 1
                    continue
                line = finding.location.line
                matching_lines = [
                    candidate["line"]
                    for candidate in candidates
                    if candidate["cwe"] == finding.vuln_class
                    and candidate["line"] is not None
                ]
                if line is None and len(matching_lines) == 1:
                    line = matching_lines[0]
                if finding.location.file is None or line != finding.location.line:
                    finding.location = Location.source(
                        file=finding.location.file or path,
                        line=line,
                    )
                findings.append(finding)

        return ConditionResult(
            findings=findings,
            usage=usage,
            trace={
                "model": ctx.model.name,
                "prompt_version": PROMPT_VERSION,
                "prompt_hashes": dict(PROMPT_HASHES),
                "files_selected": len(paths),
                "files_scanned": files_scanned,
                "files_without_candidates": files_without_candidates,
                "final_calls": final_calls,
                "model_calls": model_calls,
                "summary_parse_failures": summary_parse_failures,
                "candidate_parse_failures": candidate_parse_failures,
                "final_parse_failures": final_parse_failures,
                "invalid_candidates": invalid_candidates,
                "total_candidates": total_candidates,
                "not_supported_rejected": not_supported_rejected,
                "unexpected_findings_dropped": unexpected_findings_dropped,
                "final_findings": len(findings),
                "truncated_files": truncated_files,
                "max_file_bytes": max_bytes,
            },
            scored_cases=scored_cases,
        )


def _summary_prompt(path: str, code: str) -> str:
    return (
        f"{SUMMARY_TASK}\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{SUMMARY_CONTRACT}"
    )


def _candidate_prompt(path: str, code: str, summary: dict) -> str:
    normalized = json.dumps(summary, sort_keys=True)
    contract = CANDIDATE_CONTRACT.format(top25=SCORED_CWES)
    return (
        f"{CANDIDATE_TASK}\n\n"
        f"File: {path}\n```\n{code}\n```\n\n"
        f"Normalized summary:\n{normalized}\n\n{contract}"
    )


def _verify_prompt(path: str, code: str, summary: dict, candidates: list[dict]) -> str:
    normalized_summary = json.dumps(summary, sort_keys=True)
    normalized_candidates = json.dumps({"candidates": candidates}, sort_keys=True)
    return (
        f"{VERIFY_TASK}\n\n"
        f"File: {path}\n```\n{code}\n```\n\n"
        f"Normalized summary:\n{normalized_summary}\n\n"
        f"Normalized candidates:\n{normalized_candidates}\n\n{OUTPUT_CONTRACT}"
    )


def _fallback_verify_prompt(path: str, code: str, summary: dict) -> str:
    normalized_summary = json.dumps(summary, sort_keys=True)
    return (
        f"{FALLBACK_VERIFY_TASK}\n\n"
        f"File: {path}\n```\n{code}\n```\n\n"
        f"Normalized summary:\n{normalized_summary}\n\n{OUTPUT_CONTRACT}"
    )


def _parse_summary(text: str) -> tuple[dict, bool]:
    obj = _extract_json_object(text)
    required_arrays = (
        "untrusted_inputs",
        "sensitive_operations",
        "data_flows",
        "mitigations",
    )
    if (
        not isinstance(obj, dict)
        or not isinstance(obj.get("summary"), str)
        or any(not isinstance(obj.get(key), list) for key in required_arrays)
    ):
        return dict(_SUMMARY_UNAVAILABLE), False
    normalized = {
        "summary": obj.get("summary") if isinstance(obj.get("summary"), str) else "",
        "untrusted_inputs": _string_list(obj.get("untrusted_inputs")),
        "sensitive_operations": _string_list(obj.get("sensitive_operations")),
        "data_flows": _string_list(obj.get("data_flows")),
        "mitigations": _string_list(obj.get("mitigations")),
    }
    return normalized, True


def _parse_candidates(text: str) -> tuple[list[dict], bool, int]:
    obj = _extract_json_object(text)
    items = obj.get("candidates") if isinstance(obj, dict) else None
    if not isinstance(items, list):
        return [], False, 0
    candidates: list[dict] = []
    invalid = 0
    for item in items:
        if not isinstance(item, dict):
            invalid += 1
            continue
        cwe = _cwe_id(item.get("cwe"))
        if cwe not in _SCORED_IDS:
            invalid += 1
            continue
        candidates.append(
            {
                "cwe": cwe,
                "line": _int_or_none(item.get("line")),
                "source": _string_or_empty(item.get("source")),
                "sink": _string_or_empty(item.get("sink")),
                "suspected_flow": _string_or_empty(item.get("suspected_flow")),
                "reason": _string_or_empty(item.get("reason")),
                "mitigation_to_verify": _string_or_none(
                    item.get("mitigation_to_verify")
                ),
            }
        )
    if items and not candidates:
        return [], False, invalid
    return candidates, True, invalid


def _parse_final(text: str, source_condition: str) -> tuple[list[Finding], bool]:
    obj = _extract_json_object(text)
    if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
        return [], False
    return parse_findings(text, source_condition), True


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _string_or_empty(value: object) -> str:
    return value if isinstance(value, str) else ""


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None
