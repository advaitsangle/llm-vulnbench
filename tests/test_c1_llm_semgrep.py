"""Unit tests for C1 (LLM + Semgrep triage), focused on the phased split.

The one-pass C1 path is exercised end-to-end elsewhere (harness e2e + the live
runs); here we pin the scan_out / scan_in phasing and validation, which is the
new behavior, without needing a real Semgrep or model.
"""

from __future__ import annotations

import json

import pytest

import vulnbench.conditions.c1_llm_semgrep as c1_mod
from vulnbench.conditions.base import ConditionContext
from vulnbench.conditions.c1_llm_semgrep import C1LLMSemgrep
from vulnbench.corpus import Target, TargetKind
from vulnbench.models import Completion, Usage
from vulnbench.models.registry import MockBackend
from vulnbench.schema import Finding, Location, dump_findings


class _CapturingModel(MockBackend):
    """Records the prompts it is asked to complete; returns one confirmed finding."""

    def __init__(self):
        super().__init__()
        self.name = "fake"
        self.calls: list[str] = []

    def _complete(self, messages, tools=None, **kwargs):
        self.calls.append(messages[-1]["content"])
        return Completion(
            text=json.dumps({"findings": [
                {"cwe": 89, "file": None, "line": 12,
                 "verdict": "confirmed", "confidence": 0.9, "evidence": "tainted query"}
            ]}),
            usage=Usage(input_tokens=5, output_tokens=7),
        )


def _semgrep_finding(path: str) -> Finding:
    return Finding(
        vuln_class=89,
        location=Location.source(file=path, line=12),
        source_condition="C1",
        rule_id="java.sqli",
        message="possible SQL injection",
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_c1_requires_source_for_scan():
    target = Target(name="t", kind=TargetKind.BENCHMARK)  # no source_path
    with pytest.raises(ValueError, match="source_path"):
        C1LLMSemgrep().validate(target, ConditionContext(model=MockBackend()))


def test_c1_scan_only_needs_no_model():
    target = Target(name="t", kind=TargetKind.BENCHMARK, source_path="/tmp")
    ctx = ConditionContext(model=None, config={"scan_out": "/tmp/x.json"})
    C1LLMSemgrep().validate(target, ctx)  # no raise


def test_c1_triage_only_needs_no_source():
    target = Target(name="t", kind=TargetKind.BENCHMARK)  # no source_path
    ctx = ConditionContext(model=MockBackend(), config={"scan_in": "/tmp/x.json"})
    C1LLMSemgrep().validate(target, ctx)  # no raise


# ---------------------------------------------------------------------------
# Phased flow
# ---------------------------------------------------------------------------

def test_c1_triage_only_loads_findings_and_reads_source(tmp_path):
    src = tmp_path / "Vuln.java"
    src.write_text("String q = \"SELECT * FROM users WHERE id=\" + id; // line 1\n")
    artifact = tmp_path / "semgrep.json"
    dump_findings([_semgrep_finding(str(src))], str(artifact))

    model = _CapturingModel()
    target = Target(name="t", kind=TargetKind.BENCHMARK)
    result = C1LLMSemgrep().run(
        target, ConditionContext(model=model, config={"scan_in": str(artifact)})
    )

    assert len(model.calls) == 1                       # one file group from the artifact
    assert "SELECT * FROM users" in model.calls[0]      # source was read into the prompt
    assert "possible SQL injection" in model.calls[0]   # the loaded finding was listed
    assert result.trace["phase"] == "triage"
    assert result.trace["loaded_findings"] == 1
    assert len(result.findings) == 1
    # The triaged finding inherits the file path when the model omits it.
    assert result.findings[0].location.file == str(src)


def test_c1_triage_only_skips_semgrep(tmp_path, monkeypatch):
    artifact = tmp_path / "semgrep.json"
    dump_findings([_semgrep_finding(str(tmp_path / "x.java"))], str(artifact))
    (tmp_path / "x.java").write_text("code\n")

    def explode(*a, **k):
        raise AssertionError("run_semgrep must not be called in triage-only mode")

    monkeypatch.setattr(c1_mod, "run_semgrep", explode)

    C1LLMSemgrep().run(
        Target(name="t", kind=TargetKind.BENCHMARK),
        ConditionContext(model=_CapturingModel(), config={"scan_in": str(artifact)}),
    )  # no raise == semgrep was not invoked
