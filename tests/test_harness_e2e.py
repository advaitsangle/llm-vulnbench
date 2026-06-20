import json

from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models import MockBackend


def _make_benchmark(tmp_path):
    """A 2-file Benchmark-style fixture: one real SQLi case, one safe case."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text(
        "// vulnerable\nString q = \"SELECT * FROM u WHERE id=\" + req.getParameter(\"id\");\n"
    )
    (src / "BenchmarkTest00002.java").write_text("// safe\nint x = 1 + 1;\n")
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
    )
    return Target(
        name="fixture",
        kind=TargetKind.BENCHMARK,
        source_path=str(src),
        ground_truth=str(csv),
    )


def test_b3_with_scripted_model_detects_real_case(tmp_path):
    target = _make_benchmark(tmp_path)

    # A scripted model that flags CWE-89 on whichever file it's shown. The B3
    # condition pins the finding to the scanned file, so test 00001 is detected.
    class FlagSQLi(MockBackend):
        def _complete(self, messages, tools=None, **kwargs):
            user = messages[-1]["content"]
            if "BenchmarkTest00001" in user:
                self.scripted = json.dumps(
                    {"findings": [{"cwe": 89, "verdict": "confirmed", "confidence": 0.9,
                                   "evidence": "string concat into SQL"}]}
                )
            else:
                self.scripted = json.dumps({"findings": []})
            return super()._complete(messages, tools, **kwargs)

    record, findings = run_one(target, "B3", model=FlagSQLi())
    assert record.error is None
    assert record.metrics["tp"] == 1   # detected the real case
    assert record.metrics["fp"] == 0   # did not flag the safe case
    assert record.metrics["fn"] == 0
    assert record.metrics["tn"] == 1


def test_condition_error_is_captured_not_raised(tmp_path):
    # A validation failure (B1 with no source) becomes a recorded error, not a crash.
    target = Target("nosrc", TargetKind.BENCHMARK)
    record, _ = run_one(target, "B1", model=MockBackend())
    assert record.error is not None
    assert "source_path" in record.error
