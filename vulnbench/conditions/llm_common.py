"""Shared LLM plumbing for the B3/C1/C2 conditions.

The contract follows Gaikwad et al. (webllm): the model must return strict JSON
with grounded verdicts (evidence + counter-evidence), not prose. Constraining the
output this way is what made their findings scorable and cut hallucination. We
parse that JSON back into the common :class:`Finding` schema.
"""

from __future__ import annotations

import json
import re

from ..schema import Finding, Location, LocationKind, Verdict

#: Reused across LLM conditions; kept low per the webllm temperature finding.
SYSTEM_PROMPT = (
    "You are a precise application-security analyst. You identify web "
    "vulnerabilities and report them as strict JSON. You never fabricate "
    "findings: every reported vulnerability must cite concrete supporting "
    "evidence from the provided material, and you must note disconfirming "
    "evidence when it exists. When unsure, prefer the 'candidate' or "
    "'not_supported' verdict over 'confirmed'. You classify every finding using "
    "ONLY a CWE id drawn from the MITRE CWE Top 25 list you are given; if the "
    "best fit is not on that list, pick the single closest entry that is."
)

#: The 2023 MITRE CWE Top 25 — the closed label set the model must classify into.
#: A fixed, industry-standard taxonomy (not this benchmark's own categories), so
#: "the model knew the bug but emitted the wrong number" is separable from "the
#: model could not detect the bug" without teaching to the test.
TOP25_CWES = """\
22  Path Traversal               | 78  OS Command Injection
79  Cross-site Scripting (XSS)   | 89  SQL Injection
20  Improper Input Validation    | 77  Command Injection
94  Code Injection               | 502 Deserialization of Untrusted Data
918 Server-Side Request Forgery  | 434 Unrestricted File Upload
352 Cross-Site Request Forgery   | 287 Improper Authentication
306 Missing Authentication       | 862 Missing Authorization
863 Incorrect Authorization      | 269 Improper Privilege Management
276 Incorrect Default Permissions| 798 Hard-coded Credentials
787 Out-of-bounds Write          | 125 Out-of-bounds Read
119 Improper Memory Restriction  | 416 Use After Free
476 NULL Pointer Dereference     | 190 Integer Overflow
362 Race Condition"""

#: The required response shape. Documented inline so the model self-validates.
OUTPUT_CONTRACT = (
    "Classify each finding using ONLY a CWE id from this list (the MITRE CWE "
    "Top 25). Do not invent or use any CWE id outside it:\n"
    + TOP25_CWES
    + """

Respond with ONLY a JSON object of this exact shape (no markdown, no prose):
{
  "findings": [
    {
      "cwe": <integer CWE id — MUST be one of the Top 25 ids listed above>,
      "vuln_type": "<the plain-English name of the bug you are reporting>",
      "diagnostic": "<one sentence: the untrusted source and the dangerous sink, in your words>",
      "file": "<source file path, or null>",
      "line": <integer line number, or null>,
      "url": "<endpoint URL, or null>",
      "param": "<vulnerable parameter, or null>",
      "verdict": "confirmed" | "candidate" | "not_supported",
      "confidence": <float 0.0-1.0>,
      "evidence": "<why this is a vulnerability>",
      "counter_evidence": "<why it might not be, or null>",
      "remediation": "<one-line fix, or null>",
      "requires_human_review": <true|false>
    }
  ]
}
If you find nothing, return {"findings": []}."""
)


def parse_findings(text: str, source_condition: str) -> list[Finding]:
    """Parse the model's JSON reply into Findings.

    Tolerant of models that wrap JSON in markdown fences or add a preamble: we
    extract the outermost JSON object before parsing.
    """
    obj = _extract_json_object(text)
    if obj is None:
        return []
    items = obj.get("findings")
    if not isinstance(items, list):
        return []  # e.g. a dict or prose where the array should be
    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue  # a bare string/number can't carry a finding; skip it
        loc = _location_from(item)
        verdict = item.get("verdict")
        findings.append(
            Finding(
                vuln_class=_cwe_id(item.get("cwe")),
                location=loc,
                source_condition=source_condition,
                confidence=_clamp(item.get("confidence", 0.5)),
                verdict=Verdict(verdict) if verdict in _VERDICTS else None,
                evidence=item.get("evidence"),
                counter_evidence=item.get("counter_evidence"),
                remediation=item.get("remediation"),
                requires_human_review=bool(item.get("requires_human_review", False)),
                message=item.get("evidence"),
                extra={
                    k: item[k]
                    for k in ("vuln_type", "diagnostic")
                    if item.get(k) is not None
                },
            )
        )
    return findings


_VERDICTS = {v.value for v in Verdict}

_CWE_DIGITS_RE = re.compile(r"\d+")


def _cwe_id(x: object) -> int:
    """Coerce a model-reported CWE (89, "89", "CWE-89") to its integer id; 0 = unknown.

    The contract asks for a bare integer, but models routinely echo the label form —
    that must degrade to the right id, not crash a run mid-sweep.
    """
    try:
        return int(x)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        m = _CWE_DIGITS_RE.search(str(x or ""))
        return int(m.group(0)) if m else 0


def _location_from(item: dict) -> Location:
    if item.get("file"):
        return Location.source(file=item["file"], line=_int_or_none(item.get("line")))
    if item.get("url"):
        return Location.endpoint(url=item["url"], param=item.get("param"))
    # No coordinate given: keep a degenerate source location so it still scores.
    return Location(kind=LocationKind.SOURCE, file=item.get("file"))


def _extract_json_object(text: str) -> dict | None:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip ```json ... ``` fences or surrounding prose, grab the first {...}.
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def _clamp(x: object) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except (TypeError, ValueError):
        return 0.5


def _int_or_none(x: object) -> int | None:
    try:
        return int(x)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
