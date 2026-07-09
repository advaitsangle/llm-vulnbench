"""A1 multi-agent pipeline: scout -> hunter -> verifier, all pure-LLM.

A role-aware MockBackend returns a different scripted reply per role (detected by
the system prompt), so one model object drives all three phases deterministically.
"""

import json

from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models import MockBackend
from vulnbench.models.base import Completion, Usage


def _benchmark(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text(
        "String q = \"SELECT * FROM u WHERE id=\" + req.getParameter(\"id\");\n"
    )
    (src / "BenchmarkTest00002.java").write_text("int x = 1 + 1;\n")
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text(
        "# name, category, real, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
    )
    return Target("fix", TargetKind.BENCHMARK, source_path=str(src), ground_truth=str(csv))


class RoleBackend(MockBackend):
    """Scripts each role. ``verifier_verdict`` controls whether candidates survive."""

    def __init__(self, verifier_verdict: str = "confirmed", scout_risk: float = 0.9):
        super().__init__()
        self.verifier_verdict = verifier_verdict
        self.scout_risk = scout_risk

    def _complete(self, messages, tools=None, **kwargs):
        sys = messages[0]["content"]
        user = messages[1]["content"]
        if "triage scout" in sys:
            # Echo every path we were shown, with the configured risk.
            paths = [ln.split("### FILE: ", 1)[1] for ln in user.splitlines()
                     if ln.startswith("### FILE: ")]
            self.scripted = json.dumps(
                {"files": [{"path": p, "risk": self.scout_risk, "cwe": 89,
                            "reason": "param into SQL"} for p in paths]}
            )
        elif "skeptical security verifier" in sys:
            self.scripted = json.dumps(
                {"findings": [{"cwe": 89, "verdict": self.verifier_verdict,
                               "confidence": 0.8, "evidence": "tainted flow"}]}
            )
        else:  # hunter
            self.scripted = json.dumps(
                {"findings": [{"cwe": 89, "verdict": "candidate", "confidence": 0.6,
                               "evidence": "concat"}]}
            )
        return Completion(text=self.scripted, usage=Usage())


def test_pipeline_confirms_real_case(tmp_path):
    record, findings = run_one(_benchmark(tmp_path), "A1", model=RoleBackend())
    assert record.error is None
    assert any(f.vuln_class == 89 for f in findings)
    # The hunter proposed two candidates (one per file); both reached the verifier.
    assert record.metrics["tp"] == 1  # the real case is detected


def test_verifier_drops_unsupported(tmp_path):
    # The verifier rejects everything -> no findings survive the FP filter.
    record, findings = run_one(
        _benchmark(tmp_path), "A1", model=RoleBackend(verifier_verdict="not_supported")
    )
    assert record.error is None
    assert findings == []


def test_min_risk_skips_low_scored_files(tmp_path):
    # Scout scores everything 0.1; min_risk 0.5 -> nothing is deep-dived, but the
    # surveyed files still form the scored denominator (skips score as misses).
    record, findings = run_one(
        _benchmark(tmp_path), "A1",
        model=RoleBackend(scout_risk=0.1),
        config={"min_risk": 0.5},
    )
    assert record.error is None
    assert findings == []
    assert record.metrics["fn"] == 1  # the real case was skipped, counted as missed


def test_verify_ablation_keeps_hunter_candidates(tmp_path):
    # With verify off, the hunter's candidates pass through unfiltered.
    record, findings = run_one(
        _benchmark(tmp_path), "A1", model=RoleBackend(), config={"verify": False}
    )
    assert record.error is None
    assert any(f.vuln_class == 89 for f in findings)
