"""Unit tests for C2 (LLM + ZAP triage) — no live ZAP, no live model.

Covers the triage helpers, validation, the one-pass flow, and the phased
scan_out / scan_in split that lets the ZAP scan and the model run separately.
"""

from __future__ import annotations

import json

import pytest

import vulnbench.conditions.c2_llm_zap as c2_mod
from vulnbench.conditions import get_condition
from vulnbench.conditions.base import ConditionContext
from vulnbench.conditions.c2_llm_zap import C2LLMZap, _endpoint_key, _triage_prompt
from vulnbench.corpus import Target, TargetKind
from vulnbench.models import Completion, MockBackend, Usage
from vulnbench.scanners.zap_runner import findings_from_zap_alerts, run_zap
from vulnbench.schema import Finding, dump_findings

# Realistic ZAP alerts (as core/view/alerts returns) pointing at Benchmark cases.
SQLI_ALERT = {
    "alert": "SQL Injection",
    "description": "SQL injection may be possible.",
    "cweid": "89",
    "url": "https://localhost:8443/benchmark/sqli-00/BenchmarkTest00008",
    "method": "POST",
    "param": "username",
    "risk": "High",
    "confidence": "Medium",
    "pluginId": "40018",
    "attack": "' OR '1'='1",
    "evidence": "syntax error",
}

XSS_ALERT = {
    "alert": "Cross Site Scripting (Reflected)",
    "cweid": "79",
    "url": "https://localhost:8443/benchmark/xss-00/BenchmarkTest00042",
    "method": "GET",
    "param": "q",
    "risk": "High",
    "confidence": "Medium",
    "pluginId": "40012",
    "attack": "<script>alert(1)</script>",
    "evidence": "<script>alert(1)</script>",
}


def _findings(*alerts) -> list[Finding]:
    return findings_from_zap_alerts(list(alerts), source_condition="C2")


# ---------------------------------------------------------------------------
# Fake ZAP client (same pattern as test_zap_runner.py)
# ---------------------------------------------------------------------------

class _FakeZap:
    def __init__(self, alerts):
        self._alerts = alerts
        self.calls = []

    def version(self):
        return "2.17.0"

    def spider(self, base_url):
        self.calls.append(("spider", base_url))
        return "0"

    def spider_status(self, _):
        return 100

    def active_scan(self, base_url, recurse=True):
        self.calls.append(("ascan", base_url, recurse))
        return "1"

    def active_scan_status(self, _):
        return 100

    def alerts(self, base_url, start=0, count=0):
        return self._alerts

    def send_request(self, raw_request, follow_redirects=True):
        self.calls.append(("send", raw_request))
        return {}

    def disable_scanners(self, ids):
        self.calls.append(("disable", ids))
        return {}


# ---------------------------------------------------------------------------
# Fake model: records prompts; echoes one confirmed finding for the prompt's CWE.
# ---------------------------------------------------------------------------

class _OneFindingModel(MockBackend):
    def __init__(self):
        super().__init__()
        self.name = "fake"
        self.calls: list[str] = []

    def _complete(self, messages, tools=None, **kwargs):
        cue = messages[-1]["content"]
        self.calls.append(cue)
        cwe = 89 if "CWE-89" in cue else 79
        return Completion(
            text=json.dumps({"findings": [
                {"cwe": cwe, "verdict": "confirmed", "confidence": 0.9, "evidence": "test"}
            ]}),
            usage=Usage(input_tokens=10, output_tokens=20),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _patch_run_zap(monkeypatch, fake_zap):
    """Make C2.scan drive our fake ZAP client through run_zap."""

    def fake(base_url, **kwargs):
        source_condition = kwargs.get("source_condition", "C2")
        return run_zap(base_url, client=fake_zap, poll_interval=0, source_condition=source_condition)

    monkeypatch.setattr(c2_mod, "run_zap", fake)


def _target(base_url="https://localhost:8443/benchmark/"):
    return Target(name="bench", kind=TargetKind.BENCHMARK, base_url=base_url)


# ---------------------------------------------------------------------------
# Helper-function tests
# ---------------------------------------------------------------------------

def test_endpoint_key_strips_query_params():
    assert _endpoint_key("https://host:8443/path?foo=bar") == "https://host:8443/path"


def test_endpoint_key_strips_trailing_slash():
    assert _endpoint_key("https://host/path/") == "https://host/path"


def test_triage_prompt_contains_endpoint_and_evidence():
    prompt = _triage_prompt("https://host/login", _findings(SQLI_ALERT))
    assert "POST https://host/login" in prompt
    assert "CWE-89" in prompt
    assert "SQL Injection" in prompt        # carried in the finding's message
    assert "username" in prompt             # location.param
    assert "syntax error" in prompt         # extra['evidence']
    assert "' OR '1'='1" in prompt          # extra['attack']


def test_triage_prompt_includes_output_contract():
    prompt = _triage_prompt("https://host/login", _findings(SQLI_ALERT))
    assert '"findings"' in prompt
    assert "confirmed" in prompt


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_c2_requires_base_url():
    target = Target(name="t", kind=TargetKind.BENCHMARK, source_path="/tmp")
    with pytest.raises(ValueError, match="base_url"):
        C2LLMZap().validate(target, ConditionContext(model=MockBackend()))


def test_c2_requires_model_for_triage():
    target = _target()
    with pytest.raises(ValueError, match="model"):
        C2LLMZap().validate(target, ConditionContext(model=None))


def test_c2_scan_only_needs_no_model():
    # Phase 1 (scan_out, no scan_in) must validate without a model.
    target = _target()
    ctx = ConditionContext(model=None, config={"scan_out": "/tmp/x.json"})
    C2LLMZap().validate(target, ctx)  # no raise


def test_c2_triage_only_needs_no_base_url():
    # Phase 2 (scan_in) must validate without a running app.
    target = Target(name="t", kind=TargetKind.BENCHMARK)
    ctx = ConditionContext(model=MockBackend(), config={"scan_in": "/tmp/x.json"})
    C2LLMZap().validate(target, ctx)  # no raise


def test_c2_registered():
    assert get_condition("C2") is C2LLMZap


# ---------------------------------------------------------------------------
# One-pass (full) flow
# ---------------------------------------------------------------------------

def test_c2_no_alerts_yields_no_findings_and_no_llm_call(monkeypatch):
    fake_zap = _FakeZap([])
    _patch_run_zap(monkeypatch, fake_zap)
    model = _OneFindingModel()
    result = C2LLMZap().run(_target(), ConditionContext(model=model))
    assert result.findings == []
    assert model.calls == []
    assert result.trace["phase"] == "full"


def test_c2_single_alert_produces_finding(monkeypatch):
    fake_zap = _FakeZap([SQLI_ALERT])
    _patch_run_zap(monkeypatch, fake_zap)
    result = C2LLMZap().run(_target(), ConditionContext(model=_OneFindingModel()))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.vuln_class == 89
    assert f.source_condition == "C2"
    assert f.verdict is not None


def test_c2_two_alerts_same_endpoint_one_llm_call(monkeypatch):
    fake_zap = _FakeZap([SQLI_ALERT, dict(SQLI_ALERT, param="password")])
    _patch_run_zap(monkeypatch, fake_zap)
    model = _OneFindingModel()
    C2LLMZap().run(_target(), ConditionContext(model=model))
    assert len(model.calls) == 1  # same URL path -> one grouped call


def test_c2_two_alerts_different_endpoints_two_llm_calls(monkeypatch):
    fake_zap = _FakeZap([SQLI_ALERT, XSS_ALERT])
    _patch_run_zap(monkeypatch, fake_zap)
    model = _OneFindingModel()
    C2LLMZap().run(_target(), ConditionContext(model=model))
    assert len(model.calls) == 2


def test_c2_trace_and_usage(monkeypatch):
    fake_zap = _FakeZap([SQLI_ALERT, XSS_ALERT])
    _patch_run_zap(monkeypatch, fake_zap)
    result = C2LLMZap().run(_target(), ConditionContext(model=_OneFindingModel()))
    t = result.trace
    assert t["model"] == "fake"
    assert t["zap_raw_findings"] == 2
    assert t["endpoints_reviewed"] == 2
    # Two LLM calls, each 10 in / 20 out.
    assert result.usage.input_tokens == 20
    assert result.usage.output_tokens == 40


def test_c2_mock_model_returns_empty(monkeypatch):
    fake_zap = _FakeZap([SQLI_ALERT])
    _patch_run_zap(monkeypatch, fake_zap)
    result = C2LLMZap().run(_target(), ConditionContext(model=MockBackend()))
    assert result.findings == []


# ---------------------------------------------------------------------------
# Phased flow: scan_out (phase 1) then scan_in (phase 2)
# ---------------------------------------------------------------------------

def test_c2_scan_only_saves_findings_and_skips_model(monkeypatch, tmp_path):
    fake_zap = _FakeZap([SQLI_ALERT, XSS_ALERT])
    _patch_run_zap(monkeypatch, fake_zap)
    model = _OneFindingModel()
    out = tmp_path / "alerts.json"
    result = C2LLMZap().run(
        _target(), ConditionContext(model=model, config={"scan_out": str(out)})
    )
    # No triage in scan-only mode.
    assert model.calls == []
    assert result.trace["phase"] == "scan"
    # The saved artifact holds the raw scanner findings.
    saved = json.loads(out.read_text())
    assert len(saved) == 2
    assert {f["vuln_class"] for f in saved} == {89, 79}
    # Returned findings are the untriaged scanner findings.
    assert len(result.findings) == 2


def test_c2_triage_only_loads_findings_and_skips_zap(monkeypatch, tmp_path):
    # Pre-save a scan artifact, then triage it with ZAP guaranteed not to run.
    artifact = tmp_path / "alerts.json"
    dump_findings(_findings(SQLI_ALERT, XSS_ALERT), str(artifact))

    def explode(*a, **k):
        raise AssertionError("run_zap must not be called in triage-only mode")

    monkeypatch.setattr(c2_mod, "run_zap", explode)

    model = _OneFindingModel()
    target = Target(name="t", kind=TargetKind.BENCHMARK)  # no base_url needed
    result = C2LLMZap().run(
        target, ConditionContext(model=model, config={"scan_in": str(artifact)})
    )
    assert len(model.calls) == 2          # one per endpoint, from the loaded file
    assert len(result.findings) == 2
    assert result.trace["phase"] == "triage"
    assert result.trace["loaded_findings"] == 2


def test_c2_phased_equals_one_pass(monkeypatch, tmp_path):
    """scan_out -> scan_in must produce the same triaged findings as one pass."""
    alerts = [SQLI_ALERT, XSS_ALERT, dict(SQLI_ALERT, param="password")]

    # One-pass reference.
    fake_zap = _FakeZap(alerts)
    _patch_run_zap(monkeypatch, fake_zap)
    one_pass = C2LLMZap().run(_target(), ConditionContext(model=_OneFindingModel()))

    # Phase 1: scan only.
    fake_zap2 = _FakeZap(alerts)
    _patch_run_zap(monkeypatch, fake_zap2)
    out = tmp_path / "a.json"
    C2LLMZap().run(_target(), ConditionContext(model=None, config={"scan_out": str(out)}))

    # Phase 2: triage only.
    phase2 = C2LLMZap().run(
        Target(name="t", kind=TargetKind.BENCHMARK),
        ConditionContext(model=_OneFindingModel(), config={"scan_in": str(out)}),
    )

    assert len(phase2.findings) == len(one_pass.findings)
    assert {f.vuln_class for f in phase2.findings} == {f.vuln_class for f in one_pass.findings}
