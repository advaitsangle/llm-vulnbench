"""A7 — few-shot labeled examples.

Runs fully offline via a message-recording backend, so prompt *shape* is asserted
directly rather than inferred from counters.
"""

from __future__ import annotations

import json

from vulnbench.conditions.a7_fewshot import EXAMPLES
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

    def test_shots_zero_is_clamped_to_one_example(self, tmp_path):
        """A7 cannot be configured into being B3: zero examples floors at one.

        A condition that can be switched off still reports under its own name, so
        the floor is what keeps an A7 row in the scorecard an actual A7 run.
        """
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        record, _ = run_one(_benchmark(tmp_path), "A7", model=backend, config={"shots": 0})

        first_call = backend.calls[0]
        assert len(first_call) == 4, (
            f"expected 4 messages (sys + 1 example pair + real), got {len(first_call)}"
        )
        assert record.trace["shots"] == 1, "trace must record the post-clamp count"

    def test_trace_records_the_shots_actually_shown(self, tmp_path):
        backend = RecordingBackend(replies=[_EMPTY_REPLY, _EMPTY_REPLY])
        record, _ = run_one(_benchmark(tmp_path), "A7", model=backend, config={"shots": 2})
        assert record.trace["shots"] == 2

    def test_a7_declares_no_cot_knob(self, tmp_path):
        """A7 and A8 are separate conditions; neither carries the other's knob.

        Sharing a knob namespace would make `--condition A7 A8 --config {...}` set
        both cells at once, and there would be no way to vary one independently.
        """
        from vulnbench.conditions import get_condition
        a7_knobs = {k.name for k in get_condition("A7").all_knobs()}
        a8_knobs = {k.name for k in get_condition("A8").all_knobs()}
        assert "cot" not in a7_knobs and "fewshot" not in a7_knobs
        assert "shots" not in a8_knobs
        assert a7_knobs - a8_knobs == {"shots"}

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

