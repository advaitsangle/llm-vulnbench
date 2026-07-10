"""A1 — Multi-agent roles (pure-LLM, no scanners).

Where B3 is one flat LLM pass per file, A1 decomposes the hunt into three
cooperating roles on the *same* model backend, with role-to-role handoff:

  1. **Scout (triage)** — a cheap, wide pass. Reads only the *head* of each file
     (imports, signatures, request-handling declarations) in batches and rates
     each file's attack surface: a risk score, a single suspected CWE, and a
     one-line reason. It finds nothing; it decides where to look.
  2. **Hunter (deep-dive)** — a focused pass. Full-reads each file the scout kept,
     *primed* with the scout's suspicion ("possible CWE-89 here because ..."),
     and reports candidate findings in the shared JSON contract.
  3. **Verifier** — an adversarial pass. Re-reads each candidate against its code
     and keeps it only if a concrete source->sink data flow supports it; the rest
     are dropped. This is the false-positive filter (webllm's single biggest lever:
     18.6% -> 7.2% hallucination after a grounded re-check).

The point is a falsifiable claim (the `Sifting the Noise` question): does
decomposing the model's reasoning into scout/hunter/verifier roles beat a flat B3
pass? Each role is ablatable via config (``triage``, ``verify``) so each one's
contribution is measurable on its own.

Fairness / scoring. The scout surveys *every* in-scope file (up to ``max_files``),
so A1's scored denominator is identical to B3's at the same cap: a file the scout
declines to deep-dive is still counted, so a planted vuln the pipeline skips scores
as a false negative (filtering trades recall for cost, honestly). ``min_risk`` > 0
turns that filtering on — for realistic apps where reading every file is wasteful;
the default 0.0 deep-dives everything, isolating the role-decomposition effect from
the sampling effect.

Config knobs are declared in :attr:`A1MultiAgent.knobs`.
"""

from __future__ import annotations

import os
from collections import defaultdict

from ..corpus import Target
from ..models import Usage
from ..schema import Finding, Location, Verdict, benchmark_case_of
from .base import Condition, ConditionContext, ConditionResult, Knob
from .llm_common import (
    OUTPUT_CONTRACT,
    SYSTEM_PROMPT,
    _clamp,
    _extract_json_object,
    _int_or_none,
    parse_findings,
)
from .source_files import SCAN_KNOBS, iter_source_files, read_capped

# --- Role 1: Scout (triage) -------------------------------------------------

SCOUT_SYSTEM = (
    "You are a security triage scout. You do NOT confirm vulnerabilities; you "
    "rapidly judge which files are worth a deep security review. From imports, "
    "method signatures, and request-handling code you assess attack surface: does "
    "untrusted input (HTTP params, headers, cookies, request bodies) reach a "
    "dangerous sink (SQL, OS command, file path, deserialization, reflection, "
    "template, redirect)? You are shown only the top of each file."
)

SCOUT_CONTRACT = """\
Respond with ONLY a JSON object of this exact shape (no markdown, no prose):
{
  "files": [
    {
      "path": "<the file path exactly as given>",
      "risk": <float 0.0-1.0, how likely this file contains a web vulnerability>,
      "cwe": <the single most likely CWE id as an integer, or null>,
      "reason": "<one short clause: the source->sink concern, or why it looks benign>"
    }
  ]
}
Include every file you were shown. 'risk' is the chance the file is worth a closer
look, not a verdict."""

# --- Role 3: Verifier -------------------------------------------------------

VERIFIER_SYSTEM = (
    "You are a skeptical security verifier. You are given candidate vulnerabilities "
    "another analyst reported, together with the source code. For each, CONFIRM it "
    "only if you can cite the concrete tainted data flow from an untrusted source to "
    "the dangerous sink; otherwise mark it 'not_supported'. Reject when the flow is "
    "absent, sanitized, or unreachable, and reject when in doubt. Do not invent new "
    "findings."
)


class A1MultiAgent(Condition):
    id = "A1"
    label = "Multi-agent roles (scout/hunt/verify)"
    needs_model = True
    needs_source = True
    knobs = SCAN_KNOBS + (
        Knob("triage", "bool", True,
             help="run the scout role (off = a flat B3-like pass, plus the verifier)"),
        Knob("verify", "bool", True,
             help="run the verifier role (off = no false-positive filter)"),
        Knob("triage_head_bytes", "int", 1500,
             help="bytes from the head of each file the scout sees"),
        Knob("triage_batch", "int", 10, help="files per scout call"),
        Knob("min_risk", "float", 0.0,
             help="deep-dive only files the scout scored at or above this (0 = all)"),
    )

    def run(self, target: Target, ctx: ConditionContext) -> ConditionResult:
        assert ctx.model is not None
        max_files = int(self.cfg(ctx, "max_files")) or None
        max_bytes = int(self.cfg(ctx, "max_file_bytes"))
        head_bytes = int(self.cfg(ctx, "triage_head_bytes"))
        batch = max(1, int(self.cfg(ctx, "triage_batch")))
        min_risk = float(self.cfg(ctx, "min_risk"))
        do_triage = bool(self.cfg(ctx, "triage"))
        do_verify = bool(self.cfg(ctx, "verify"))

        paths = list(iter_source_files(target.source_path, max_files))
        # Denominator is every file surveyed — same as B3 at this cap — so skipping
        # a file for deep-dive is scored as a missed case, not hidden from scoring.
        scored_cases = {tc for p in paths if (tc := benchmark_case_of(p)) is not None}

        usage = Usage()

        # Role 1: scout decides where to look (and what to suspect).
        if do_triage:
            risk, scout_usage = self._scout(paths, ctx, head_bytes, batch)
            usage = usage + scout_usage
        else:
            risk = {}

        if do_triage and min_risk > 0:
            deep = [p for p in paths if risk.get(p, {}).get("risk", 0.0) >= min_risk]
        else:
            deep = paths

        # Role 2: hunter deep-dives the kept files, primed by the scout's hunch.
        candidates, hunt_usage = self._hunt(deep, ctx, max_bytes, risk)
        usage = usage + hunt_usage

        # Role 3: verifier drops anything it can't ground in a real data flow.
        if do_verify and candidates:
            findings, verify_usage, rejected = self._verify(candidates, ctx, max_bytes)
            usage = usage + verify_usage
        else:
            findings, rejected = candidates, 0

        return ConditionResult(
            findings=findings,
            usage=usage,
            trace={
                "model": ctx.model.name,
                "files_surveyed": len(paths),
                "files_deep_dived": len(deep),
                "files_skipped_by_scout": len(paths) - len(deep),
                "candidates": len(candidates),
                "verified_findings": len(findings),
                "rejected_by_verifier": rejected,
                "triage": do_triage,
                "verify": do_verify,
                "min_risk": min_risk,
            },
            scored_cases=scored_cases or None,
        )

    def _scout(
        self, paths: list[str], ctx: ConditionContext, head_bytes: int, batch: int
    ) -> tuple[dict[str, dict], Usage]:
        assert ctx.model is not None
        risk: dict[str, dict] = {}
        usage = Usage()
        for i in range(0, len(paths), batch):
            chunk = paths[i : i + batch]
            chunk_set = set(chunk)
            # Fallback lookup for models that don't echo the path verbatim, but only
            # for basenames that are *unique* in this batch — otherwise a nested tree
            # with two same-named files would misattribute the scout's risk.
            by_base = _unique_basenames(chunk)
            blocks = []
            for p in chunk:
                head, _ = read_capped(p, head_bytes)
                blocks.append(f"### FILE: {p}\n```\n{head}\n```")
            messages = [
                {"role": "system", "content": SCOUT_SYSTEM},
                {"role": "user", "content": _scout_prompt(blocks)},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage
            for entry in _parse_scout(completion.text):
                # Trust only paths we actually showed it (exact, else by basename).
                p = entry["path"]
                real = p if p in chunk_set else by_base.get(os.path.basename(p))
                if real:
                    entry["path"] = real
                    risk[real] = entry
        return risk, usage

    def _hunt(
        self, paths: list[str], ctx: ConditionContext, max_bytes: int, risk: dict[str, dict]
    ) -> tuple[list[Finding], Usage]:
        assert ctx.model is not None
        candidates: list[Finding] = []
        usage = Usage()
        for p in paths:
            code, _ = read_capped(p, max_bytes)
            if not code:
                continue
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _hunt_prompt(p, code, risk.get(p))},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage
            for f in parse_findings(completion.text, self.id):
                if f.location.file is None:
                    f.location = Location.source(file=p, line=f.location.line)
                candidates.append(f)
        return candidates, usage

    def _verify(
        self, candidates: list[Finding], ctx: ConditionContext, max_bytes: int
    ) -> tuple[list[Finding], Usage, int]:
        assert ctx.model is not None
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in candidates:
            by_file[f.location.file or ""].append(f)

        kept: list[Finding] = []
        usage = Usage()
        for path, group in by_file.items():
            code, _ = read_capped(path, max_bytes) if path else ("", False)
            messages = [
                {"role": "system", "content": VERIFIER_SYSTEM},
                {"role": "user", "content": _verify_prompt(path, code, group)},
            ]
            completion = ctx.model.complete(messages)
            usage = usage + completion.usage
            for f in parse_findings(completion.text, self.id):
                # The verifier's job is to drop the unsupported; a candidate it
                # doesn't re-affirm is gone too. Surviving ones keep its verdict.
                if f.verdict is Verdict.NOT_SUPPORTED:
                    continue
                if f.location.file is None and path:
                    f.location = Location.source(file=path, line=f.location.line)
                kept.append(f)
        return kept, usage, len(candidates) - len(kept)


def _scout_prompt(blocks: list[str]) -> str:
    listing = "\n\n".join(blocks)
    return (
        "Triage these source files for security review. For each, judge how likely "
        "it is to contain a real web vulnerability based on whether untrusted input "
        "reaches a dangerous sink. You see only the top of each file.\n\n"
        f"{listing}\n\n{SCOUT_CONTRACT}"
    )


def _hunt_prompt(path: str, code: str, hint: dict | None) -> str:
    lead = ""
    if hint:
        cwe = hint.get("cwe")
        cwe_txt = f"CWE-{cwe}" if cwe else "a vulnerability"
        lead = (
            f'A triage scout flagged this file as possibly containing {cwe_txt}: '
            f'"{hint.get("reason") or ""}". Investigate that concern, but also report '
            "any other genuine vulnerability. Do NOT confirm the scout's guess unless "
            "the code actually supports it.\n\n"
        )
    return (
        f"{lead}Analyze this source file for security vulnerabilities.\n\n"
        f"File: {path}\n```\n{code}\n```\n\n{OUTPUT_CONTRACT}"
    )


def _verify_prompt(path: str, code: str, group: list[Finding]) -> str:
    listed = "\n".join(
        f"- CWE-{f.vuln_class} at line {f.location.line}: {f.evidence or f.message or ''}"
        for f in group
    )
    return (
        "Another analyst reported these candidate vulnerabilities in this file. For "
        "each, confirm it ONLY if you can cite the concrete data flow from an untrusted "
        "source to the sink; otherwise mark it 'not_supported'. Keep the confirmed and "
        "plausible ('candidate') ones; drop the rest.\n\n"
        f"File: {path}\n\nCandidates:\n{listed}\n\n"
        f"Source:\n```\n{code}\n```\n\n{OUTPUT_CONTRACT}"
    )


def _unique_basenames(paths: list[str]) -> dict[str, str]:
    """Map basename -> path, dropping any basename that occurs more than once."""
    seen: dict[str, str] = {}
    dupes: set[str] = set()
    for p in paths:
        base = os.path.basename(p)
        if base in seen:
            dupes.add(base)
        seen[base] = p
    return {b: p for b, p in seen.items() if b not in dupes}


def _parse_scout(text: str) -> list[dict]:
    obj = _extract_json_object(text)
    if not obj:
        return []
    items = obj.get("files")
    if not isinstance(items, list):
        return []
    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        out.append(
            {
                "path": item["path"],
                "risk": _clamp(item.get("risk", 0.0)),
                "cwe": _int_or_none(item.get("cwe")),
                "reason": item.get("reason") or "",
            }
        )
    return out
