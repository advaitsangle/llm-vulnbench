"""A8 — chain-of-thought.

Runs fully offline via a message-recording backend, so prompt *shape* is asserted
directly rather than inferred from counters.
"""

from __future__ import annotations

import json

from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models.base import Completion, ModelBackend, Usage

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _benchmark(tmp_path):
    """Two-file OWASP-Benchmark-style fixture."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text(
        'String q = "SELECT * FROM u WHERE id=" + req.getParameter("id");\n'
    )
    (src / "BenchmarkTest00002.java").write_text("int x = 1 + 1;\n")
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text(
        "# name, category, real, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
    )
    return Target("fix", TargetKind.BENCHMARK, source_path=str(src), ground_truth=str(csv))


_FINDING_REPLY = json.dumps({
    "findings": [{
        "cwe": 89,
        "vuln_type": "SQL Injection",
        "diagnostic": "param into SQL",
        "file": None,
        "line": 1,
        "url": None,
        "param": "id",
        "verdict": "confirmed",
        "confidence": 0.9,
        "evidence": "concat",
        "counter_evidence": None,
        "remediation": "use PreparedStatement",
        "requires_human_review": False,
    }]
})

_COT_FINDING_REPLY = json.dumps({
    "analysis": [
        "Entry point: req.getParameter('id') is untrusted.",
        "Sink: string concatenated into SQL query.",
        "No parameterization or escaping present.",
        "Confirmed SQL injection.",
    ],
    "findings": [{
        "cwe": 89,
        "vuln_type": "SQL Injection",
        "diagnostic": "param into SQL",
        "file": None,
        "line": 1,
        "url": None,
        "param": "id",
        "verdict": "confirmed",
        "confidence": 0.9,
        "evidence": "concat",
        "counter_evidence": None,
        "remediation": "use PreparedStatement",
        "requires_human_review": False,
    }]
})

_EMPTY_REPLY = json.dumps({"findings": []})


# ---------------------------------------------------------------------------
# Recording backend
# ---------------------------------------------------------------------------

class RecordingBackend(ModelBackend):
    """Captures the last message list passed to complete(). Scripted per call."""

    def __init__(self, replies: list[str] | None = None) -> None:
        self.name = "mock-recording"
        self._replies = list(replies or [])
        self._call_idx = 0
        self.calls: list[list[dict]] = []

    def _complete(self, messages, tools=None, **kwargs):
        self.calls.append(list(messages))
        if self._replies:
            text = self._replies[self._call_idx % len(self._replies)]
            self._call_idx += 1
        else:
            text = _EMPTY_REPLY
        return Completion(text=text, usage=Usage())


class TestA8ChainOfThought:
    def test_cot_prompt_demands_analysis_before_findings(self, tmp_path):
        """The final user turn must mention 'analysis' before 'findings'."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A8", model=backend)

        user_content = backend.calls[0][-1]["content"]
        analysis_pos = user_content.find('"analysis"')
        findings_pos = user_content.find('"findings"')
        assert analysis_pos != -1, "'analysis' key not found in the CoT prompt"
        assert findings_pos != -1, "'findings' key not found in the CoT prompt"
        assert analysis_pos < findings_pos, (
            "'analysis' must appear before 'findings' in the prompt so the model "
            "reasons left-to-right"
        )

    def test_cot_system_suffix_added(self, tmp_path):
        """The system prompt for A8 includes the CoT reasoning instruction."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A8", model=backend)

        sys_content = backend.calls[0][0]["content"]
        assert "reason step by step" in sys_content.lower() or "step by step" in sys_content

    def test_cot_reply_parsed_and_reasoning_attached(self, tmp_path):
        """A reply with analysis + findings: analysis lands in finding.extra."""
        backend = RecordingBackend(replies=[_COT_FINDING_REPLY, _EMPTY_REPLY])
        _, findings = run_one(_benchmark(tmp_path), "A8", model=backend)

        assert findings, "expected at least one finding"
        f = findings[0]
        assert "cot_analysis" in f.extra, "CoT analysis steps not attached to finding.extra"
        assert isinstance(f.extra["cot_analysis"], list)
        assert len(f.extra["cot_analysis"]) > 0

    def test_cot_compliance_counted_in_trace(self, tmp_path):
        """trace must record how many files produced a valid analysis array."""
        backend = RecordingBackend(replies=[_COT_FINDING_REPLY, _EMPTY_REPLY])
        record, _ = run_one(_benchmark(tmp_path), "A8", model=backend)
        assert record.error is None
        trace = record.trace
        assert "cot_followed_count" in trace, "cot_followed_count not in trace"
        assert "cot_followed_frac" in trace, "cot_followed_frac not in trace"

    def test_missing_analysis_still_parses(self, tmp_path):
        """A reply with no analysis array parses normally; the trace counts the gap."""
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        record, findings = run_one(_benchmark(tmp_path), "A8", model=backend)
        assert record.error is None
        # findings still parsed
        assert isinstance(findings, list)
        # cot_followed_count is less than files_scanned (0 out of 2)
        trace = record.trace
        assert trace["cot_followed_count"] == 0
        for f in findings:
            assert "cot_analysis" not in f.extra

    def test_a8_never_sends_examples(self, tmp_path):
        """A8 always sends system + one user turn — it has no few-shot path at all.

        Structural, not a default: pairing the CoT prompt (which demands an analysis
        array) with A7's example replies (which have none) would demonstrate ignoring
        the instruction, and cot_followed_frac would measure the prompt, not the model.
        """
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A8", model=backend)

        first_call = backend.calls[0]
        assert len(first_call) == 2, (
            f"A8 default should have 2 messages (system+user), got {len(first_call)}"
        )

    def test_a8_finding_pinned_to_scanned_path(self, tmp_path):
        """A finding with file=null is resolved to the scanned file."""
        backend = RecordingBackend(replies=[_COT_FINDING_REPLY, _EMPTY_REPLY])
        _, findings = run_one(_benchmark(tmp_path), "A8", model=backend)

        assert findings
        for f in findings:
            assert f.location.file is not None
            assert "BenchmarkTest" in (f.location.file or "")

    def test_a8_tp_is_detected(self, tmp_path):
        """The real CWE-89 case scores as a true positive."""
        backend = RecordingBackend(replies=[_COT_FINDING_REPLY, _EMPTY_REPLY])
        record, _ = run_one(_benchmark(tmp_path), "A8", model=backend)
        assert record.error is None
        assert record.metrics["tp"] == 1

