"""A7 few-shot / A8 chain-of-thought conditions.

All tests run fully offline using a message-recording MockBackend subclass
that captures the full message list so prompt shape can be asserted directly.
"""

from __future__ import annotations

import json

from vulnbench.conditions.a7_a8_fewshot_cot import EXAMPLES
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


# ---------------------------------------------------------------------------
# A7 few-shot tests
# ---------------------------------------------------------------------------

class TestA7FewShot:
    def test_fewshot_turns_precede_real_file(self, tmp_path):
        """A7 prepends example user/assistant turns before the real file's turn."""
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A7", model=backend)

        # Each file gets its own call; inspect the first call.
        assert backend.calls, "no model calls were made"
        first_call = backend.calls[0]

        # system + pairs of (user, assistant) examples + final user turn
        shots = 4  # default
        expected_len = 1 + shots * 2 + 1
        assert len(first_call) == expected_len, (
            f"expected {expected_len} messages (sys+{shots}*2 example turns+1 real), "
            f"got {len(first_call)}"
        )
        assert first_call[0]["role"] == "system"
        # Pairs alternate user/assistant for the examples.
        for i in range(shots):
            assert first_call[1 + i * 2]["role"] == "user"
            assert first_call[2 + i * 2]["role"] == "assistant"
        # Final turn is the real file.
        assert first_call[-1]["role"] == "user"

    def test_real_file_is_last_user_turn(self, tmp_path):
        """The actual file path appears in the last user turn, not an example."""
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A7", model=backend)

        last_user = backend.calls[0][-1]
        assert "BenchmarkTest" in last_user["content"], (
            "real file path not found in the last user message"
        )

    def test_shots_knob_caps_example_count(self, tmp_path):
        """shots=2 results in exactly 2 example pairs (1*user + 1*assistant each)."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A7", model=backend, config={"shots": 2})

        first_call = backend.calls[0]
        # 1 system + 2*2 example turns + 1 real = 6
        assert len(first_call) == 6, f"expected 6 messages with shots=2, got {len(first_call)}"

    def test_shots_zero_sends_no_examples(self, tmp_path):
        """shots=0 means no example turns — same shape as B3."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A7", model=backend, config={"shots": 0})

        first_call = backend.calls[0]
        assert len(first_call) == 2, (
            f"expected 2 messages (sys+user) with shots=0, got {len(first_call)}"
        )

    def test_fewshot_false_matches_b3_shape(self, tmp_path):
        """fewshot=false on A7 sends a bare system+user pair matching B3."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A7", model=backend, config={"fewshot": False})

        first_call = backend.calls[0]
        assert len(first_call) == 2, (
            f"fewshot=False should produce 2 messages like B3, got {len(first_call)}"
        )
        assert first_call[0]["role"] == "system"
        assert first_call[1]["role"] == "user"

    def test_example_count_does_not_exceed_builtin_pool(self, tmp_path):
        """shots larger than the built-in pool is silently capped."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A7", model=backend, config={"shots": 100})

        first_call = backend.calls[0]
        # Cannot exceed 1 + len(EXAMPLES)*2 + 1
        max_expected = 1 + len(EXAMPLES) * 2 + 1
        assert len(first_call) == max_expected

    def test_examples_contain_both_labels(self, tmp_path):
        """At least one example must be safe (empty findings) to avoid all-positive bias."""
        safe_examples = [ex for ex in EXAMPLES if '"findings": []' in ex.reply]
        vuln_examples = [ex for ex in EXAMPLES if '"findings": []' not in ex.reply]
        assert safe_examples, "no safe (empty-findings) examples found"
        assert vuln_examples, "no vulnerable examples found"

    def test_a7_finding_pinned_to_scanned_path(self, tmp_path):
        """A finding with file=null must be resolved to the file that was scanned."""
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        _, findings = run_one(_benchmark(tmp_path), "A7", model=backend)

        assert findings, "expected at least one finding"
        for f in findings:
            assert f.location.file is not None, "finding location.file must not be None"
            assert "BenchmarkTest" in (f.location.file or "")

    def test_a7_tp_is_detected(self, tmp_path):
        """The real CWE-89 case scores as a true positive."""
        backend = RecordingBackend(replies=[_FINDING_REPLY, _EMPTY_REPLY])
        record, _ = run_one(_benchmark(tmp_path), "A7", model=backend)
        assert record.error is None
        assert record.metrics["tp"] == 1


# ---------------------------------------------------------------------------
# A8 chain-of-thought tests
# ---------------------------------------------------------------------------

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
        assert "cot_followed_pct" in trace, "cot_followed_pct not in trace"

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

    def test_a8_no_fewshot_by_default(self, tmp_path):
        """A8's default call is system + single user turn (no example pairs)."""
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


# ---------------------------------------------------------------------------
# Combined few-shot + CoT
# ---------------------------------------------------------------------------

class TestCombined:
    def test_a7_with_cot_true_adds_analysis_prefix(self, tmp_path):
        """A7 with cot=true includes both example turns and the analysis prefix."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        run_one(_benchmark(tmp_path), "A7", model=backend, config={"cot": True, "shots": 2})

        first_call = backend.calls[0]
        # 1 system + 2 example pairs (4 turns) + 1 real = 6
        assert len(first_call) == 6

        user_content = first_call[-1]["content"]
        assert '"analysis"' in user_content, "CoT analysis key missing from combined prompt"

    def test_a8_with_fewshot_true_includes_examples(self, tmp_path):
        """A8 with fewshot=true prepends example turns before the real file."""
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        shots = 3
        run_one(_benchmark(tmp_path), "A8", model=backend,
                config={"fewshot": True, "shots": shots})

        first_call = backend.calls[0]
        expected_len = 1 + shots * 2 + 1
        assert len(first_call) == expected_len
        # Final user turn must still contain the analysis prefix.
        assert '"analysis"' in first_call[-1]["content"]
