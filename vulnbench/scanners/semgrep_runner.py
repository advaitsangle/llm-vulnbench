"""Run Semgrep and normalize its JSON output to :class:`Finding`.

Semgrep is the primary SAST tool: multi-language, deterministic,
and the baseline used by the comparison papers, which makes B1 comparable to prior
work. The B1 baseline is itself a *config choice* — we fix one ruleset and record
it. The default here is ``p/owasp-top-ten`` because the OWASP Benchmark is labeled
by CWE/Top-Ten categories.

Semgrep tags many rules with a CWE in ``extra.metadata.cwe``; we parse the numeric
id out of strings like ``"CWE-89: SQL Injection"``. Findings whose rule carries no
CWE are kept with ``vuln_class = 0`` (unknown) so nothing is silently dropped.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from ..schema import Finding, Location


def _resolve_semgrep() -> str | None:
    """Find the semgrep executable.

    Checks PATH first, then the directory of the running interpreter, so a
    ``semgrep`` installed into the same venv as vulnbench is found even when the
    venv's ``bin`` is not on the subprocess PATH.
    """
    found = shutil.which("semgrep")
    if found:
        return found
    candidate = os.path.join(os.path.dirname(sys.executable), "semgrep")
    return candidate if os.path.exists(candidate) else None


def _require_semgrep() -> str:
    """Resolve semgrep or raise an actionable install hint."""
    semgrep_bin = _resolve_semgrep()
    if semgrep_bin is None:
        raise FileNotFoundError(
            "semgrep not found on PATH or next to the Python interpreter. "
            "Install with `pip install semgrep` (into this venv), "
            "`pipx install semgrep`, or `brew install semgrep`, then re-run."
        )
    return semgrep_bin


def validate_rules(rules_path: str, timeout: float = 60.0) -> tuple[bool, str]:
    """Run ``semgrep --validate`` on a rules file.

    Returns ``(ok, message)``. Used by C3 to check that LLM-authored Semgrep YAML
    is syntactically valid *before* it is run as a scored scanner — a malformed
    rule would otherwise crash the scan or, worse, silently match nothing.
    """
    semgrep_bin = _require_semgrep()
    cmd = [semgrep_bin, "--validate", "--config", rules_path]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    message = (proc.stderr or proc.stdout).strip()
    return proc.returncode == 0, message

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

#: Frozen default ruleset for the B1 baseline. Documented and version-pinned in
#: scored runs; override per condition config if needed.
DEFAULT_RULESET = "p/owasp-top-ten"


def parse_cwe(metadata: dict) -> int:
    """Extract a single CWE id from a Semgrep rule's metadata block."""
    cwe = metadata.get("cwe")
    candidates = cwe if isinstance(cwe, list) else [cwe]
    for c in candidates:
        if not c:
            continue
        m = _CWE_RE.search(str(c))
        if m:
            return int(m.group(1))
    return 0  # unknown / unmapped


@dataclass
class SemgrepResult:
    """Raw + normalized output of one Semgrep run."""

    findings: list[Finding]
    raw: dict = field(default_factory=dict)
    command: list[str] = field(default_factory=list)
    version: str | None = None  # Semgrep version, for scorecard provenance


def findings_from_semgrep_json(data: dict, source_condition: str = "B1") -> list[Finding]:
    """Convert a parsed ``semgrep --json`` document into normalized findings.

    Split out from :func:`run_semgrep` so the parser is unit-testable on fixtures
    without Semgrep installed.
    """
    findings: list[Finding] = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {}) or {}
        start = r.get("start", {}) or {}
        findings.append(
            Finding(
                vuln_class=parse_cwe(meta),
                location=Location.source(
                    file=r.get("path", ""),
                    line=start.get("line"),
                    column=start.get("col"),
                ),
                source_condition=source_condition,
                confidence=_confidence(meta.get("confidence")),
                rule_id=r.get("check_id"),
                message=(r.get("extra", {}).get("message") or "").strip() or None,
            )
        )
    return findings


def _confidence(label: object) -> float:
    """Map Semgrep's HIGH/MEDIUM/LOW confidence label to a number in [0,1]."""
    return {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}.get(str(label).upper(), 0.7)


def run_semgrep(
    target_path: str,
    config: str = DEFAULT_RULESET,
    source_condition: str = "B1",
    extra_args: list[str] | None = None,
    timeout: float = 1800.0,
) -> SemgrepResult:
    """Run Semgrep over ``target_path`` and return normalized findings.

    Raises ``FileNotFoundError`` with an install hint if Semgrep is absent so the
    failure is actionable rather than a bare ``No such file``.
    """
    semgrep_bin = _require_semgrep()
    cmd = [semgrep_bin, "--config", config, "--json", "--quiet", target_path]
    if extra_args:
        cmd[1:1] = extra_args
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    # Semgrep returns non-zero when findings exist; only treat empty stdout as error.
    if not proc.stdout.strip():
        raise RuntimeError(f"semgrep produced no output. stderr:\n{proc.stderr}")
    data = json.loads(proc.stdout)
    return SemgrepResult(
        findings=findings_from_semgrep_json(data, source_condition),
        raw=data,
        command=cmd,
        version=data.get("version"),
    )
