"""A5 — break the file down to its risky portion, then run B3's evaluation on that.

Two iterations over the same model backend:

  1. **Reducer (parse)** — reads the whole test file and returns nothing but the risky
     portion of it: the lines where untrusted input enters, the lines where it reaches a
     dangerous sink, and the assignments that carry it between them. It reports no
     vulnerability; it decides what the next pass is allowed to see.
  2. **Evaluator** — *is* B3. The same system prompt, the same user prompt (imported from
     :mod:`.b3_llm`, so it cannot drift), the same output contract and parser — with the
     reduced code in place of the file.

Keeping iteration 2 byte-identical to B3 is the whole point: A5 vs B3 over the same files
differs in exactly one variable, the code the evaluator was given. A5 winning means
pre-reducing the file helped the model; A5 losing means the reducer cut the context the
bug needed.

Fairness / scoring. Every file the reducer looks at is in the scored denominator, same as
B3 at the same cap, so a vuln the reduction drops is a false negative rather than a case
quietly removed from the run. Token and latency usage covers *both* calls, so the reducer's
cost is charged to A5 where the comparison can see it.

Two honest limitations, both measured rather than hidden:

* The chunk is text the model produced, so it may be paraphrased rather than copied.
  ``chunk_fidelity`` in the trace reports how much of it is really in the file. A finding's
  ``line`` is advisory for the same reason — Benchmark scoring is file-based, so scoring is
  unaffected.
* Because the chunk goes into B3's prompt verbatim, with no "this is an excerpt" hedge, an
  evaluator can read an omitted sanitizer as a missing one. That false-positive channel
  shows up as ``pruned_frac`` against A5's precision relative to B3.

Config knobs are declared in :attr:`A5Parse.knobs`.
"""

from __future__ import annotations

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, benchmark_case_of
from .b3_llm import _user_prompt as b3_user_prompt
from .base import Condition, ConditionContext, ConditionResult, Knob
from .llm_common import SYSTEM_PROMPT, _extract_json_object, parse_findings
from .source_files import (
    SAMPLE_KNOBS,
    SCAN_KNOBS,
    iter_source_files,
    read_capped,
    sampled_paths_for,
)

REDUCER_SYSTEM = (
    "You are a code reducer for a security review pipeline. You do NOT judge "
    "vulnerabilities and you do NOT rewrite, reformat, or summarize code: you copy out "
    "the portion of a file that another analyst must read. Keep the lines where "
    "untrusted input enters (HTTP params, headers, cookies, request bodies, files), the "
    "lines where it reaches a dangerous sink (SQL, OS command, file path, "
    "deserialization, reflection, template, redirect, response write), and the "
    "assignments that carry the data between them. Drop imports, boilerplate, comments, "
    "and unrelated methods. Every line you return must appear character-for-character in "
    "the file you were given."
)

REDUCER_CONTRACT = """\
Respond with ONLY a JSON object of this exact shape (no markdown, no prose):
{
  "chunk": "<the risky lines, copied exactly; separate non-adjacent blocks by a blank line>",
  "reason": "<one short clause: the untrusted source and the dangerous sink it reaches>"
}
Copy, never rewrite: if you cannot reproduce a line exactly, leave it out. If nothing in
the file handles untrusted data, return {"chunk": "", "reason": "<why it looks benign>"}."""


class A5Parse(Condition):
    id = "A5"
    label = "Risky-portion extraction, then B3 evaluation"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + SAMPLE_KNOBS + (
        Knob("reduce", "bool", True,
             help="run the reducer pass (off = A5 is exactly B3, the control)"),
        Knob("max_chunk_bytes", "int", 8000,
             help="truncate the reducer's extracted code past this many bytes"),
        Knob("on_empty", "str", "full", choices=("full", "skip"),
             help="reducer extracted nothing: evaluate the full file, or skip it"),
    )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))
        max_chunk = int(self.cfg(ctx, "max_chunk_bytes"))
        do_reduce = bool(self.cfg(ctx, "reduce"))
        on_empty = str(self.cfg(ctx, "on_empty"))

        # --sample overrides max_files: the smoke slice *is* the file set.
        sampled = sampled_paths_for(self, ctx, target.source_path)
        paths = sampled if sampled is not None else list(
            iter_source_files(target.source_path, max_files)
        )

        findings: list[Finding] = []
        usage = Usage()
        scored_cases: set[str] = set()
        evaluated = 0
        reduced = 0
        fell_back = 0
        skipped = 0
        source_chars = 0
        chunk_chars = 0
        fidelities: list[float] = []

        for path in paths:
            tc = benchmark_case_of(path)
            if tc is not None:
                scored_cases.add(tc)  # in scope even if the reduction hides the bug
            code, _ = read_capped(path, max_bytes)
            if not code:
                continue
            source_chars += len(code)

            # Iteration 1: reduce the file to its risky portion.
            if not do_reduce:
                chunk = code
            else:
                chunk, reduce_usage = self._reduce(path, code, ctx)
                usage = usage + reduce_usage
                if max_chunk > 0:
                    chunk = chunk[:max_chunk]
                if chunk.strip():
                    reduced += 1
                    fidelities.append(_fidelity(chunk, code))
                elif on_empty == "skip":
                    # The reducer found nothing worth reading; take it at its word.
                    skipped += 1
                    continue
                else:
                    # An empty (or unparseable) reduction falls back to plain B3 on this
                    # file, counted apart so a fallback never reads as an A5 result.
                    fell_back += 1
                    chunk = code

            chunk_chars += len(chunk)

            # Iteration 2: B3's evaluation, verbatim, over the reduced code.
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": b3_user_prompt(path, chunk)},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage
            for f in parse_findings(completion.text, self.id):
                # Pin the location to the file the chunk came from, as B3 does.
                if f.location.file is None:
                    f.location = Location.source(file=path, line=f.location.line)
                findings.append(f)
            evaluated += 1

        return ConditionResult(
            findings=findings,
            usage=usage,
            trace={
                "model": ctx.model.name,
                "reduce": do_reduce,
                "files_evaluated": evaluated,
                "files_reduced": reduced,
                "files_full_fallback": fell_back,
                "files_skipped_empty": skipped,
                "source_chars": source_chars,
                "chunk_chars": chunk_chars,
                # Share of the source text read that never reached the evaluator, so
                # 0.0 = forwarded everything. Files skipped under on_empty="skip" count
                # here too (they forwarded nothing); files_skipped_empty separates them.
                "pruned_frac": (
                    round(1 - chunk_chars / source_chars, 3) if source_chars else 0.0
                ),
                # How much of the forwarded code was really in the file (1.0 = all of it).
                "chunk_fidelity": (
                    round(sum(fidelities) / len(fidelities), 3) if fidelities else None
                ),
            },
            # Score only over what we looked at (respects max_files/--sample).
            scored_cases=scored_cases or None,
        )

    def _reduce(self, path: str, code: str, ctx: ConditionContext) -> tuple[str, Usage]:
        """Ask the model for the file's risky portion; returns ``(chunk, usage)``.

        The contract also asks for a one-clause ``reason``, which makes the reducer
        commit to a source->sink rationale for what it keeps. We deliberately don't
        consume it: forwarding it would prime the evaluator, and storing it per file
        would bloat every scorecard on a 2740-file sweep.
        """
        assert ctx.model is not None
        messages = [
            {"role": "system", "content": REDUCER_SYSTEM},
            {"role": "user", "content": _reduce_prompt(path, code)},
        ]
        completion = ctx.model.complete(messages)
        obj = _extract_json_object(completion.text) or {}
        chunk = obj.get("chunk")
        return chunk if isinstance(chunk, str) else "", completion.usage


def _reduce_prompt(path: str, code: str) -> str:
    return (
        "Copy out only the risky portion of this file: the untrusted-input sources, the "
        "dangerous sinks, and the assignments that carry data between them. Leave "
        "everything else out. Do not rewrite what you keep.\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{REDUCER_CONTRACT}"
    )


def _fidelity(chunk: str, code: str) -> float:
    """Share of the chunk's non-blank lines that occur verbatim in ``code``.

    Whitespace-normalized per line, so re-indentation doesn't read as fabrication while a
    paraphrased or invented statement still does. 1.0 means the reducer only ever copied;
    anything less means the evaluator was handed code that is not in the file. Reported,
    not enforced — A5 forwards the chunk either way, and this is how you tell whether a
    model can be trusted with a verbatim-text handoff at all.
    """
    original = {line.strip() for line in code.splitlines() if line.strip()}
    lines = [line.strip() for line in chunk.splitlines() if line.strip()]
    if not lines:
        return 1.0
    return sum(line in original for line in lines) / len(lines)
