"""A6: a structural summary of the file is produced, then B3's judgment runs over the
code plus that summary.

A stage-aware MockBackend answers the summarizer and the judge differently (told apart
by the system prompt) and records every prompt per stage, so the handoff between the
two iterations is assertable offline.
"""

import json

from vulnbench.conditions.a6_summarize import SUMMARY_BLOCK_HEADER
from vulnbench.conditions.b3_llm import _user_prompt as b3_user_prompt
from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models import MockBackend
from vulnbench.models.base import Completion, Usage

SINK = 'String q = "SELECT * FROM u WHERE id=" + req.getParameter("id");'
BOILERPLATE = "\n".join(f"import java.util.pkg{n}.Thing{n};" for n in range(6))

#: A contract-shaped summary, already in normalized form, so tests can predict the
#: exact JSON the judge is handed: ``json.dumps(HONEST_SUMMARY, sort_keys=True)``.
HONEST_SUMMARY = {
    "overview": "A servlet that builds a SQL query from a request parameter.",
    "classes": [
        {"name": "BenchmarkTest", "purpose": "request handler",
         "methods": [{"name": "doGet", "signature": "(req, resp) -> void",
                      "purpose": "reads the id parameter into a query string"}]}
    ],
    "functions": [],
    "entry_points": ["servlet doGet"],
    "data_flows": ['req.getParameter("id") -> SQL query string'],
    "external_interactions": ["database query"],
}


def _benchmark(tmp_path):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "BenchmarkTest00001.java").write_text(f"{BOILERPLATE}\n{SINK}\n")
    (src / "BenchmarkTest00002.java").write_text(f"{BOILERPLATE}\nint x = 1 + 1;\n")
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text(
        "# name, category, real, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
    )
    return Target("fix", TargetKind.BENCHMARK, source_path=str(src), ground_truth=str(csv))


class SummaryBackend(MockBackend):
    """Scripts both iterations.

    ``summary_reply=None`` (the default) is an honest summarizer: it returns
    ``HONEST_SUMMARY`` as clean contract JSON. Pass a ``summary_reply`` to script a
    specific stage-1 reply — garbage to exercise the malformed paths, or messy JSON
    to exercise normalization.
    """

    def __init__(self, summary_reply: str | None = None):
        super().__init__()
        self.summary_reply = summary_reply
        self.summary_prompts: list[str] = []
        self.judge_prompts: list[str] = []

    def _complete(self, messages, tools=None, **kwargs):
        sys = messages[0]["content"]
        user = messages[1]["content"]
        if "do NOT judge" in sys:  # the summarizer
            self.summary_prompts.append(user)
            text = self.summary_reply if self.summary_reply is not None else json.dumps(HONEST_SUMMARY)
        else:  # the judge — B3's own system prompt
            self.judge_prompts.append(user)
            text = json.dumps(
                {"findings": [{"cwe": 89, "verdict": "confirmed", "confidence": 0.8,
                               "evidence": "tainted concat"}]}
            )
        return Completion(text=text, usage=Usage(input_tokens=1, output_tokens=1))


def test_judge_sees_the_code_and_the_summary(tmp_path):
    model = SummaryBackend()
    record, findings = run_one(_benchmark(tmp_path), "A6", model=model)
    assert record.error is None
    assert any(f.vuln_class == 89 for f in findings)
    assert record.metrics["tp"] == 1  # the real case is detected
    # The judge got the whole file — summary is additive, never a replacement.
    assert any(SINK in p for p in model.judge_prompts)
    assert all('"overview"' in p for p in model.judge_prompts)
    assert record.trace["files_scanned"] == 2
    assert record.trace["model_calls"] == 4
    assert record.trace["summary_overhead_frac"] > 0


def test_judge_prompt_ends_with_b3s_prompt(tmp_path):
    """Iteration 2 *is* B3: the summary is a prefix, B3's exact prompt the suffix."""
    target = _benchmark(tmp_path)
    model = SummaryBackend()
    run_one(target, "A6", model=model)
    path = f"{target.source_path}/BenchmarkTest00001.java"
    code = f"{BOILERPLATE}\n{SINK}\n"
    assert any(p.endswith(b3_user_prompt(path, code)) for p in model.judge_prompts)


def test_summary_is_normalized_before_the_handoff(tmp_path):
    # Fenced, pretty-printed, with an extra key: none of that may reach the judge.
    messy = "```json\n" + json.dumps({"internal_notes": "drop me", **HONEST_SUMMARY}, indent=2) + "\n```"
    model = SummaryBackend(summary_reply=messy)
    record, _ = run_one(_benchmark(tmp_path), "A6", model=model)
    assert record.error is None
    assert record.trace["summary_parse_failures"] == 0
    expected = json.dumps(HONEST_SUMMARY, sort_keys=True)
    assert all(expected in p for p in model.judge_prompts)
    assert all("```json" not in p for p in model.judge_prompts)
    assert all("internal_notes" not in p for p in model.judge_prompts)


def test_both_passes_are_billed(tmp_path):
    model = SummaryBackend()
    record, _ = run_one(_benchmark(tmp_path), "A6", model=model)
    # Two files x (one summarizer call + one judge call).
    assert len(model.summary_prompts) == 2
    assert len(model.judge_prompts) == 2
    assert record.input_tokens == 4  # the summarizer's cost is charged to A6, not hidden


def test_summarize_off_is_plain_b3(tmp_path):
    target = _benchmark(tmp_path)
    model = SummaryBackend()
    record, findings = run_one(target, "A6", model=model, config={"summarize": False})
    assert record.error is None
    assert model.summary_prompts == []  # no summary pass at all
    path = f"{target.source_path}/BenchmarkTest00001.java"
    # Exact equality, not endswith: the control arm carries no prefix of any kind.
    assert b3_user_prompt(path, f"{BOILERPLATE}\n{SINK}\n") in model.judge_prompts
    assert record.trace["model_calls"] == 2
    assert any(f.vuln_class == 89 for f in findings)


def test_malformed_summary_degrades_to_code_only(tmp_path):
    model = SummaryBackend(summary_reply="this is not json")
    record, findings = run_one(_benchmark(tmp_path), "A6", model=model)
    assert record.error is None
    assert record.trace["summary_parse_failures"] == 2
    assert record.trace["files_judged_code_only"] == 2
    # The judge fell back to plain B3 on both files: no summary block anywhere.
    assert all(SUMMARY_BLOCK_HEADER not in p for p in model.judge_prompts)
    assert record.metrics["tp"] == 1  # a bad summarizer costs its tokens, not recall


def test_on_malformed_skip_leaves_the_file_unjudged(tmp_path):
    model = SummaryBackend(summary_reply="this is not json")
    record, findings = run_one(
        _benchmark(tmp_path), "A6", model=model, config={"on_malformed": "skip"}
    )
    assert record.error is None
    assert model.judge_prompts == []
    assert findings == []
    assert record.trace["files_skipped_malformed"] == 2
    assert record.metrics["fn"] == 1  # skipping costs recall, honestly


def test_max_summary_bytes_truncates_the_handoff(tmp_path):
    model = SummaryBackend()
    record, _ = run_one(
        _benchmark(tmp_path), "A6", model=model, config={"max_summary_bytes": 10}
    )
    assert record.error is None
    assert record.trace["summaries_truncated"] == 2
    full = json.dumps(HONEST_SUMMARY, sort_keys=True)
    assert all(full[:10] in p and full not in p for p in model.judge_prompts)


def test_findings_are_pinned_to_the_scanned_file(tmp_path):
    # The judge reply carries no "file": A6 must pin it, as B3 does.
    record, findings = run_one(_benchmark(tmp_path), "A6", model=SummaryBackend())
    assert findings
    assert all(f.location.file is not None for f in findings)
    assert any(f.location.file.endswith("BenchmarkTest00001.java") for f in findings)


def test_trace_records_prompt_provenance(tmp_path):
    record, _ = run_one(_benchmark(tmp_path), "A6", model=SummaryBackend())
    assert record.trace["prompt_version"] == "a6-summarize-v1"
    assert set(record.trace["prompt_hashes"]) == {"summary", "judge"}
    hexdigits = set("0123456789abcdef")
    assert all(
        len(h) == 64 and set(h) <= hexdigits
        for h in record.trace["prompt_hashes"].values()
    )
