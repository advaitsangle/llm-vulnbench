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
    "'not_supported' verdict over 'confirmed'."
)

#: The required response shape. Documented inline so the model self-validates.
OUTPUT_CONTRACT = """\
Respond with ONLY a JSON object of this exact shape (no markdown, no prose):
{
  "findings": [
    {
      "cwe": <integer CWE id, e.g. 89>,
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


def parse_findings(text: str, source_condition: str) -> list[Finding]:
    """Parse the model's JSON reply into Findings.

    Tolerant of models that wrap JSON in markdown fences or add a preamble: we
    extract the outermost JSON object before parsing.
    """
    obj = _extract_json_object(text)
    if obj is None:
        return []
    findings: list[Finding] = []
    for item in obj.get("findings", []):
        loc = _location_from(item)
        verdict = item.get("verdict")
        findings.append(
            Finding(
                vuln_class=int(item.get("cwe") or 0),
                location=loc,
                source_condition=source_condition,
                confidence=_clamp(item.get("confidence", 0.5)),
                verdict=Verdict(verdict) if verdict in _VERDICTS else None,
                evidence=item.get("evidence"),
                counter_evidence=item.get("counter_evidence"),
                remediation=item.get("remediation"),
                requires_human_review=bool(item.get("requires_human_review", False)),
                message=item.get("evidence"),
            )
        )
    return findings


_VERDICTS = {v.value for v in Verdict}


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
