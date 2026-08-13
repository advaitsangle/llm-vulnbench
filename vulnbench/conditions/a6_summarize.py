"""A6 — summarize the file top-down, then run B3's judgment over code + summary.

Two iterations over the same model backend:

  1. **Summarizer** — reads the whole file and describes its structure top-down: what
     the file is for, its classes and their methods, its top-level functions, how
     execution enters, and how data moves. It gives no security verdict; it produces
     orientation for the next pass.
  2. **Judge** — *is* B3. The same system prompt, the same user prompt (imported from
     :mod:`.b3_llm`, so it cannot drift), the same output contract and parser — with
     the normalized summary prefixed as an extra context block above it.

The judge always sees the original code; the summary is additive. So A6 vs B3 over the
same files differs in exactly one variable: whether a structural summary preceded the
code. ``summarize=False`` removes the prefix entirely and A6 is byte-identical B3, the
control arm.

Fairness / scoring. Every file enters the scored denominator before the summary pass
runs, so a summarizer failure can never quietly remove a case from the run — it is a
counted degradation (judge on code alone) or a counted skip, per the ``on_malformed``
knob. Token and latency usage covers both calls, so the summarizer's cost is charged to
A6 where the comparison can see it.

One honest limitation, measured rather than hidden: the summary is model prose about
the code, so a wrong summary can prime a wrong judgment. That channel is the
experimental variable, not a bug — the summary is deliberately security-neutral (no
taint or mitigation vocabulary) so A6 asks "does plain comprehension scaffolding
help?", distinct from a security-primed summary stage.

Config knobs are declared in :attr:`A6Summarize.knobs`.
"""

from __future__ import annotations

import hashlib
import json

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, benchmark_case_of
from .b3_llm import _user_prompt as b3_user_prompt
from .base import Condition, ConditionContext, ConditionResult, Knob
from .llm_common import (
    OUTPUT_CONTRACT,
    SYSTEM_PROMPT,
    _extract_json_object,
    parse_findings,
)
from .source_files import (
    SAMPLE_KNOBS,
    SCAN_KNOBS,
    iter_source_files,
    read_capped,
    sampled_paths_for,
)

SUMMARY_SYSTEM = (
    "You are a precise code analyst. You describe the structure of source code: its "
    "classes, methods and functions, what each is for, and how data moves through "
    "them. You report only what is present in the code. You do NOT judge whether a "
    "vulnerability exists and you do NOT give security verdicts."
)

SUMMARY_TASK = (
    "Break this source file down top-down into its structure: what the file is for, "
    "its classes and their methods, its top-level functions, how execution enters, "
    "and how data moves. Do not make any vulnerability judgment."
)

SUMMARY_CONTRACT = """\
Respond with ONLY a JSON object of this exact shape (no markdown, no prose):
{
  "overview": "<one or two sentences: what this file is for>",
  "classes": [
    {
      "name": "<class name>",
      "purpose": "<what the class is for>",
      "methods": [
        {"name": "<method name>", "signature": "<parameters and return, briefly>",
         "purpose": "<what the method does>"}
      ]
    }
  ],
  "functions": [<top-level functions, same shape as a method>],
  "entry_points": ["<how execution enters: HTTP handler, main, servlet doGet/doPost, ...>"],
  "data_flows": ["<one flow: where a value originates, what transforms it, where it ends up>"],
  "external_interactions": ["<database, filesystem, OS command, network, or other outside touch>"]
}
Use an empty array when a category has no entries. Describe only code that is in the file."""

#: Prefixed (not spliced in) so B3's prompt stays a contiguous suffix — testable with
#: ``endswith`` — and the output contract stays last, closest to generation.
SUMMARY_BLOCK_HEADER = (
    "A prior analysis pass produced this structural summary of the file. Use it "
    "for orientation; the code below is the authority when they disagree.\n"
)

PROMPT_VERSION = "a6-summarize-v1"

PROMPT_HASHES = {
    "summary": hashlib.sha256(
        (SUMMARY_SYSTEM + SUMMARY_TASK + SUMMARY_CONTRACT).encode()
    ).hexdigest(),
    "judge": hashlib.sha256(
        (SYSTEM_PROMPT + SUMMARY_BLOCK_HEADER + OUTPUT_CONTRACT).encode()
    ).hexdigest(),
}


class A6Summarize(Condition):
    id = "A6"
    label = "Structural summary, then B3 judgment"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + SAMPLE_KNOBS + (
        Knob("summarize", "bool", True,
             help="run the summary pass (off = A6 is exactly B3, the control)"),
        Knob("on_malformed", "str", "code_only", choices=("code_only", "skip"),
             help="pass-1 summary unparseable: judge with the code alone, or skip the file"),
        Knob("max_summary_bytes", "int", 6000,
             help="truncate the normalized summary JSON past this many bytes"),
    )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))
        max_summary = int(self.cfg(ctx, "max_summary_bytes"))
        do_summarize = bool(self.cfg(ctx, "summarize"))
        on_malformed = str(self.cfg(ctx, "on_malformed"))

        # --sample overrides max_files: the smoke slice *is* the file set.
        sampled = sampled_paths_for(self, ctx, target.source_path)
        paths = sampled if sampled is not None else list(
            iter_source_files(target.source_path, max_files)
        )

        findings: list[Finding] = []
        usage = Usage()
        scored_cases: set[str] = set()
        model_calls = 0
        files_scanned = 0
        summary_parse_failures = 0
        files_judged_code_only = 0
        files_skipped_malformed = 0
        judge_parse_failures = 0
        truncated_files = 0
        summaries_truncated = 0
        source_chars = 0
        summary_chars = 0

        for path in paths:
            tc = benchmark_case_of(path)
            if tc is not None:
                scored_cases.add(tc)  # in scope even if the summary pass fails on it
            code, was_truncated = read_capped(path, max_bytes)
            if not code:
                continue
            if was_truncated:
                truncated_files += 1
            source_chars += len(code)

            # Iteration 1: describe the file's structure. No verdicts.
            summary_json: str | None = None
            if do_summarize:
                completion = ctx.model.complete([
                    {"role": "system", "content": SUMMARY_SYSTEM},
                    {"role": "user", "content": _summary_prompt(path, code)},
                ])
                usage = usage + completion.usage
                model_calls += 1
                summary, ok = _parse_summary(completion.text)
                if ok:
                    summary_json = json.dumps(summary, sort_keys=True)
                    if max_summary > 0 and len(summary_json) > max_summary:
                        summary_json = summary_json[:max_summary]
                        summaries_truncated += 1
                    summary_chars += len(summary_json)
                elif on_malformed == "skip":
                    summary_parse_failures += 1
                    files_skipped_malformed += 1
                    continue
                else:
                    # A malformed summary degrades to plain B3 on this file, counted
                    # apart so a degraded cell never reads as an A6-with-summary result.
                    summary_parse_failures += 1
                    files_judged_code_only += 1

            # Iteration 2: B3's judgment, verbatim, over the code — with the summary
            # prefixed when iteration 1 produced one.
            user = (
                _judge_prompt(path, code, summary_json)
                if summary_json is not None
                else b3_user_prompt(path, code)
            )
            completion = ctx.model.complete([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ])
            usage = usage + completion.usage
            model_calls += 1
            obj = _extract_json_object(completion.text)
            if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
                # "no parsable findings object" is a different fact from "no findings";
                # parse_findings returns [] for both, so tell them apart here.
                judge_parse_failures += 1
            for f in parse_findings(completion.text, self.id):
                # Pin the location to the file we actually scanned, as B3 does.
                if f.location.file is None:
                    f.location = Location.source(file=path, line=f.location.line)
                findings.append(f)
            files_scanned += 1

        return ConditionResult(
            findings=findings,
            usage=usage,
            trace={
                "model": ctx.model.name,
                "prompt_version": PROMPT_VERSION,
                "prompt_hashes": dict(PROMPT_HASHES),
                "summarize": do_summarize,
                "files_selected": len(paths),
                "files_scanned": files_scanned,
                "model_calls": model_calls,
                "summary_parse_failures": summary_parse_failures,
                "files_judged_code_only": files_judged_code_only,
                "files_skipped_malformed": files_skipped_malformed,
                "judge_parse_failures": judge_parse_failures,
                "truncated_files": truncated_files,
                "summaries_truncated": summaries_truncated,
                "source_chars": source_chars,
                "summary_chars": summary_chars,
                # What the handoff *added* on top of the code — the context-window
                # pressure the summary creates. 0.0 = no summary reached a judge.
                "summary_overhead_frac": (
                    round(summary_chars / source_chars, 3) if source_chars else 0.0
                ),
                "max_file_bytes": max_bytes,
            },
            # Score only over what we looked at (respects max_files/--sample).
            scored_cases=scored_cases or None,
        )


def _summary_prompt(path: str, code: str) -> str:
    return (
        f"{SUMMARY_TASK}\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{SUMMARY_CONTRACT}"
    )


def _judge_prompt(path: str, code: str, summary_json: str) -> str:
    return SUMMARY_BLOCK_HEADER + summary_json + "\n\n" + b3_user_prompt(path, code)


def _parse_summary(text: str) -> tuple[dict, bool]:
    """Parse and normalize the summarizer's reply; returns ``(summary, ok)``.

    The summary is re-serialized before it enters the judge prompt, so model prose,
    markdown fences, and unknown keys never cross the handoff. Absent categories
    normalize to empty; a present-but-wrong-type category means the model did not
    follow the contract, and the whole reply is treated as malformed.
    """
    obj = _extract_json_object(text)
    if not isinstance(obj, dict):
        return {}, False
    overview = obj.get("overview")
    if not isinstance(overview, str):
        return {}, False
    lists = {
        key: obj.get(key, [])
        for key in ("classes", "functions", "entry_points",
                    "data_flows", "external_interactions")
    }
    if not all(isinstance(value, list) for value in lists.values()):
        return {}, False
    return {
        "overview": overview,
        "classes": [_class(c) for c in lists["classes"] if isinstance(c, dict)],
        "functions": [_callable(f) for f in lists["functions"] if isinstance(f, dict)],
        "entry_points": _string_list(lists["entry_points"]),
        "data_flows": _string_list(lists["data_flows"]),
        "external_interactions": _string_list(lists["external_interactions"]),
    }, True


def _class(obj: dict) -> dict:
    methods = obj.get("methods")
    return {
        "name": _string_or_empty(obj.get("name")),
        "purpose": _string_or_empty(obj.get("purpose")),
        "methods": (
            [_callable(m) for m in methods if isinstance(m, dict)]
            if isinstance(methods, list) else []
        ),
    }


def _callable(obj: dict) -> dict:
    return {key: _string_or_empty(obj.get(key)) for key in ("name", "signature", "purpose")}


def _string_or_empty(x: object) -> str:
    return x if isinstance(x, str) else ""


def _string_list(items: list) -> list[str]:
    return [item for item in items if isinstance(item, str)]
