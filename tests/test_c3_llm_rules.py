"""Unit tests for C3 (LLM-authored Semgrep rules).

The model and Semgrep are both faked: the model returns canned YAML, and
``run_semgrep`` / ``validate_rules`` are monkeypatched, so these pin C3's wiring
(author vs score phases, YAML extraction, overfit flagging) without a real Semgrep
or LLM. The author+scan path against a live model is an overnight/manual run.
"""

from __future__ import annotations

import pytest

import vulnbench.conditions.c3_llm_rules as c3_mod
from vulnbench.conditions.base import ConditionContext
from vulnbench.conditions.c3_llm_rules import C3LLMRules, _extract_yaml
from vulnbench.corpus import Target, TargetKind
from vulnbench.models import Completion, MockBackend, Usage
from vulnbench.scanners.semgrep_runner import SemgrepResult
from vulnbench.schema import Finding, Location

_YAML = "rules:\n  - id: sqli\n    languages: [java]\n    metadata:\n      cwe: 'CWE-89'\n"


class _RuleAuthorModel(MockBackend):
    """Returns a fixed YAML ruleset and records the authoring prompt."""

    def __init__(self, text: str = _YAML):
        super().__init__()
        self.name = "fake"
        self.text = text
        self.calls: list[str] = []

    def _complete(self, messages, tools=None, **kwargs):
        self.calls.append(messages[-1]["content"])
        return Completion(text=self.text, usage=Usage(input_tokens=9, output_tokens=4))


def _src_tree(tmp_path):
    f = tmp_path / "BenchmarkTest00001.java"
    f.write_text('String q = "SELECT * FROM u WHERE id=" + req.getParameter("id");\n')
    return str(tmp_path)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_c3_authoring_requires_a_model():
    target = Target(name="t", kind=TargetKind.BENCHMARK, source_path="/tmp")
    with pytest.raises(ValueError, match="model"):
        C3LLMRules().validate(target, ConditionContext(model=None))


def test_c3_score_only_needs_no_model():
    target = Target(name="t", kind=TargetKind.BENCHMARK, source_path="/tmp")
    ctx = ConditionContext(model=None, config={"rules_in": "/tmp/rules.yaml"})
    C3LLMRules().validate(target, ctx)  # no raise


def test_c3_requires_source():
    target = Target(name="t", kind=TargetKind.BENCHMARK)  # no source_path
    ctx = ConditionContext(model=None, config={"rules_in": "/tmp/rules.yaml"})
    with pytest.raises(ValueError, match="source_path"):
        C3LLMRules().validate(target, ctx)


# ---------------------------------------------------------------------------
# Author phase (rules_out): writes YAML, runs no scanner
# ---------------------------------------------------------------------------

def test_c3_author_phase_writes_rules_and_skips_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(c3_mod, "validate_rules", lambda p, **k: (True, "ok"))

    def explode(*a, **k):
        raise AssertionError("run_semgrep must not be called in the author phase")

    monkeypatch.setattr(c3_mod, "run_semgrep", explode)

    src = _src_tree(tmp_path)
    out = tmp_path / "rules.yaml"
    model = _RuleAuthorModel()
    result = C3LLMRules().run(
        Target(name="t", kind=TargetKind.BENCHMARK, source_path=src),
        ConditionContext(model=model, config={"rules_out": str(out)}),
    )

    assert "SELECT * FROM u" in model.calls[0]        # source went into the prompt
    assert out.read_text().startswith("rules:")        # YAML was written out
    assert result.findings == []                       # author phase produces no findings
    assert result.trace["phase"] == "author"
    assert result.trace["rules_valid"] is True


# ---------------------------------------------------------------------------
# Score phase (rules_in): runs Semgrep deterministically, no model
# ---------------------------------------------------------------------------

def test_c3_score_phase_runs_semgrep_without_model(tmp_path, monkeypatch):
    src = _src_tree(tmp_path)
    finding = Finding(
        vuln_class=89,
        location=Location.source(file=f"{src}/BenchmarkTest00001.java", line=1),
        source_condition="C3",
    )
    captured = {}

    def fake_run(path, config, source_condition, timeout=1800.0):
        captured["config"] = config
        return SemgrepResult(findings=[finding], version="1.0")

    monkeypatch.setattr(c3_mod, "run_semgrep", fake_run)

    rules = tmp_path / "rules.yaml"
    rules.write_text(_YAML)
    result = C3LLMRules().run(
        Target(name="t", kind=TargetKind.BENCHMARK, source_path=src),
        ConditionContext(model=None, config={"rules_in": str(rules)}),
    )

    assert captured["config"] == str(rules)            # Semgrep ran the authored rules
    assert result.findings == [finding]
    assert result.scored_cases == {"BenchmarkTest00001"}  # honest subset scope
    assert result.trace["rules_in"] == str(rules)


# ---------------------------------------------------------------------------
# Single pass (no knobs): authors then scans the same source -> overfit flag
# ---------------------------------------------------------------------------

def test_c3_single_pass_flags_overfitting(tmp_path, monkeypatch):
    monkeypatch.setattr(c3_mod, "validate_rules", lambda p, **k: (True, "ok"))

    def fake_run(path, config, source_condition, timeout=1800.0):
        return SemgrepResult(findings=[], version="1.0")

    monkeypatch.setattr(c3_mod, "run_semgrep", fake_run)

    src = _src_tree(tmp_path)
    result = C3LLMRules().run(
        Target(name="t", kind=TargetKind.BENCHMARK, source_path=src),
        ConditionContext(model=_RuleAuthorModel(), config={}),
    )

    assert result.trace["phase"] == "author+scan"
    assert "overfit_warning" in result.trace
    # Authoring tokens are folded into the run's usage.
    assert result.usage.input_tokens == 9


# ---------------------------------------------------------------------------
# YAML extraction
# ---------------------------------------------------------------------------

def test_extract_yaml_strips_fences():
    fenced = "```yaml\nrules:\n  - id: x\n```"
    assert _extract_yaml(fenced) == "rules:\n  - id: x"


def test_extract_yaml_bare_passthrough():
    assert _extract_yaml("rules:\n  - id: x\n") == "rules:\n  - id: x"
