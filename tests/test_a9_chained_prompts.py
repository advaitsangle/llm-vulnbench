"""A9 chained prompts: summarize -> identify candidates -> verify."""

import json
import re

import pytest

from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models import Completion, MockBackend, ModelBackend, Usage
from vulnbench.schema import Verdict


def _benchmark(tmp_path, *, vulnerable: bool) -> Target:
    src = tmp_path / "src"
    src.mkdir()
    source = src / "BenchmarkTest00001.java"
    source.write_text(
        (
            'String q = "SELECT * FROM users WHERE id="'
            ' + request.getParameter("id");\n'
        )
        if vulnerable
        else "int result = 1 + 1;\n"
    )
    expected = tmp_path / "expectedresults-1.2.csv"
    expected.write_text(
        "# test name, category, real vulnerability, cwe\n"
        f"BenchmarkTest00001,sqli,{str(vulnerable).lower()},89\n"
    )
    return Target(
        name="a9-fixture",
        kind=TargetKind.BENCHMARK,
        source_path=str(src),
        ground_truth=str(expected),
    )


class ScriptedChainBackend(ModelBackend):
    name = "scripted-chain"

    def __init__(
        self,
        replies: list[dict | str],
        usages: list[Usage] | None = None,
    ) -> None:
        self._replies = [
            json.dumps(reply) if isinstance(reply, dict) else reply for reply in replies
        ]
        self._usages = list(usages or [Usage() for _ in replies])
        self.calls: list[list[dict]] = []

    def _complete(self, messages, tools=None, **kwargs):
        self.calls.append(messages)
        return Completion(text=self._replies.pop(0), usage=self._usages.pop(0))


def _summary_reply() -> dict:
    return {
        "summary": "Request input is concatenated into SQL.",
        "untrusted_inputs": ["id"],
        "sensitive_operations": ["SQL"],
        "data_flows": ["id -> SQL"],
        "mitigations": [],
    }


def _candidate_reply(*, cwe: int = 89, line: int | None = 1) -> dict:
    return {
        "candidates": [
            {
                "cwe": cwe,
                "line": line,
                "source": "id",
                "sink": "SQL",
                "suspected_flow": "id -> SQL",
                "reason": "string concatenation",
                "mitigation_to_verify": "prepared statement",
            }
        ]
    }


def _finding_reply(
    *,
    cwe: int = 89,
    verdict: str = "confirmed",
    line: int | None = 1,
) -> dict:
    return {
        "findings": [
            {
                "cwe": cwe,
                "verdict": verdict,
                "confidence": 0.9,
                "line": line,
                "evidence": "The request parameter reaches the SQL operation.",
            }
        ]
    }


def test_three_stage_chain_confirms_vulnerable_case(tmp_path):
    model = ScriptedChainBackend(
        [
            {
                "summary": "A request parameter is concatenated into a SQL query.",
                "untrusted_inputs": ["request parameter id"],
                "sensitive_operations": ["SQL query construction"],
                "data_flows": ["id -> query string"],
                "mitigations": [],
            },
            {
                "candidates": [
                    {
                        "cwe": 89,
                        "line": 1,
                        "source": "request.getParameter(\"id\")",
                        "sink": "SQL query construction",
                        "suspected_flow": "id reaches the SQL query by concatenation",
                        "reason": "Untrusted input changes query syntax.",
                        "mitigation_to_verify": "prepared statement",
                    }
                ]
            },
            {
                "findings": [
                    {
                        "cwe": 89,
                        "vuln_type": "SQL Injection",
                        "diagnostic": "Request input is concatenated into SQL.",
                        "file": None,
                        "line": 1,
                        "url": None,
                        "param": "id",
                        "verdict": "confirmed",
                        "confidence": 0.95,
                        "evidence": "The id parameter is concatenated into the query.",
                        "counter_evidence": None,
                        "remediation": "Use a prepared statement.",
                        "requires_human_review": False,
                    }
                ]
            },
        ]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=True), "A9", model=model)

    assert record.error is None
    assert record.metrics["tp"] == 1
    assert len(findings) == 1
    assert findings[0].vuln_class == 89
    assert len(model.calls) == 3
    assert all(len(messages) == 2 for messages in model.calls)
    assert all("request.getParameter" in messages[1]["content"] for messages in model.calls)
    assert '"summary": "A request parameter is concatenated' in model.calls[1][1]["content"]
    assert '"suspected_flow": "id reaches the SQL query' in model.calls[2][1]["content"]


def test_empty_candidates_skip_final_stage(tmp_path):
    model = ScriptedChainBackend(
        [
            {
                "summary": "The file performs a constant arithmetic operation.",
                "untrusted_inputs": [],
                "sensitive_operations": [],
                "data_flows": [],
                "mitigations": [],
            },
            {"candidates": []},
        ]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=False), "A9", model=model)

    assert record.error is None
    assert record.metrics["tn"] == 1
    assert findings == []
    assert len(model.calls) == 2
    assert record.trace["files_without_candidates"] == 1
    assert record.trace["final_calls"] == 0


@pytest.mark.parametrize("malformed_summary", ["not JSON", "[]"])
def test_summary_parse_failure_continues_with_unavailable_marker(
    tmp_path,
    malformed_summary,
):
    model = ScriptedChainBackend(
        [
            malformed_summary,
            {"candidates": []},
        ]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=False), "A9", model=model)

    assert record.error is None
    assert findings == []
    assert len(model.calls) == 2
    assert "summary unavailable" in model.calls[1][1]["content"].lower()
    assert record.trace["summary_parse_failures"] == 1


@pytest.mark.parametrize("malformed_candidates", [{"candidates": "none"}, "[]"])
def test_candidate_parse_failure_runs_independent_final_analysis(
    tmp_path,
    malformed_candidates,
):
    model = ScriptedChainBackend(
        [
            {
                "summary": "Request input is concatenated into SQL.",
                "untrusted_inputs": ["id"],
                "sensitive_operations": ["SQL"],
                "data_flows": ["id -> SQL"],
                "mitigations": [],
            },
            malformed_candidates,
            {
                "findings": [
                    {
                        "cwe": 89,
                        "verdict": "confirmed",
                        "confidence": 0.9,
                        "evidence": "The request parameter reaches SQL.",
                    }
                ]
            },
        ]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=True), "A9", model=model)

    assert record.error is None
    assert record.metrics["tp"] == 1
    assert len(findings) == 1
    assert len(model.calls) == 3
    assert "candidate extraction failed" in model.calls[2][1]["content"].lower()
    assert record.trace["candidate_parse_failures"] == 1


def test_nonempty_all_invalid_candidate_list_uses_fallback(tmp_path):
    model = ScriptedChainBackend(
        [
            {
                "summary": "Request input is concatenated into SQL.",
                "untrusted_inputs": ["id"],
                "sensitive_operations": ["SQL"],
                "data_flows": ["id -> SQL"],
                "mitigations": [],
            },
            {"candidates": ["CWE-89", 89]},
            {"findings": []},
        ]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=True), "A9", model=model)

    assert record.error is None
    assert findings == []
    assert len(model.calls) == 3
    assert record.trace["candidate_parse_failures"] == 1
    assert record.trace["invalid_candidates"] == 2


def test_partial_invalid_candidate_list_keeps_valid_entries(tmp_path):
    model = ScriptedChainBackend(
        [
            {
                "summary": "Request input is concatenated into SQL.",
                "untrusted_inputs": ["id"],
                "sensitive_operations": ["SQL"],
                "data_flows": ["id -> SQL"],
                "mitigations": [],
            },
            {
                "candidates": [
                    {
                        "cwe": 89,
                        "line": 1,
                        "source": "id",
                        "sink": "SQL",
                        "suspected_flow": "id -> SQL",
                        "reason": "string concatenation",
                        "mitigation_to_verify": "prepared statement",
                    },
                    "invalid candidate",
                ]
            },
            {"findings": []},
        ]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=True), "A9", model=model)

    assert record.error is None
    assert findings == []
    assert len(model.calls) == 3
    assert record.trace["candidate_parse_failures"] == 0
    assert record.trace["invalid_candidates"] == 1
    assert record.trace["total_candidates"] == 1


@pytest.mark.parametrize("malformed_final", ['{"findings": "none"}', "[]"])
def test_final_parse_failure_stops_after_third_call(tmp_path, malformed_final):
    model = ScriptedChainBackend(
        [
            {
                "summary": "Request input is concatenated into SQL.",
                "untrusted_inputs": ["id"],
                "sensitive_operations": ["SQL"],
                "data_flows": ["id -> SQL"],
                "mitigations": [],
            },
            {
                "candidates": [
                    {
                        "cwe": 89,
                        "line": 1,
                        "source": "id",
                        "sink": "SQL",
                        "suspected_flow": "id -> SQL",
                        "reason": "string concatenation",
                        "mitigation_to_verify": "prepared statement",
                    }
                ]
            },
            malformed_final,
        ]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=True), "A9", model=model)

    assert record.error is None
    assert findings == []
    assert len(model.calls) == 3
    assert record.trace["final_parse_failures"] == 1


def test_not_supported_final_finding_is_rejected(tmp_path):
    model = ScriptedChainBackend(
        [_summary_reply(), _candidate_reply(), _finding_reply(verdict="not_supported")]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=False), "A9", model=model)

    assert record.error is None
    assert findings == []
    assert record.metrics["fp"] == 0
    assert record.trace["not_supported_rejected"] == 1


def test_candidate_final_verdict_is_retained(tmp_path):
    model = ScriptedChainBackend(
        [_summary_reply(), _candidate_reply(), _finding_reply(verdict="candidate")]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=True), "A9", model=model)

    assert record.error is None
    assert record.metrics["tp"] == 1
    assert len(findings) == 1
    assert findings[0].verdict is Verdict.CANDIDATE


def test_final_finding_with_unflagged_cwe_is_dropped(tmp_path):
    model = ScriptedChainBackend(
        [_summary_reply(), _candidate_reply(cwe=89), _finding_reply(cwe=79)]
    )

    record, findings = run_one(_benchmark(tmp_path, vulnerable=False), "A9", model=model)

    assert record.error is None
    assert findings == []
    assert record.trace["unexpected_findings_dropped"] == 1


def test_missing_final_file_and_line_inherit_scanned_file_and_unique_candidate_line(
    tmp_path,
):
    model = ScriptedChainBackend(
        [_summary_reply(), _candidate_reply(cwe=89, line=7), _finding_reply(line=None)]
    )
    target = _benchmark(tmp_path, vulnerable=True)

    record, findings = run_one(target, "A9", model=model)

    assert record.error is None
    assert len(findings) == 1
    assert findings[0].location.file == str(
        tmp_path / "src" / "BenchmarkTest00001.java"
    )
    assert findings[0].location.line == 7


def test_missing_final_line_is_not_inherited_from_multiple_same_cwe_candidates(
    tmp_path,
):
    candidates = _candidate_reply(cwe=89, line=7)
    candidates["candidates"].append(dict(candidates["candidates"][0]))
    model = ScriptedChainBackend(
        [_summary_reply(), candidates, _finding_reply(line=None)]
    )

    record, findings = run_one(
        _benchmark(tmp_path, vulnerable=True),
        "A9",
        model=model,
    )

    assert record.error is None
    assert len(findings) == 1
    assert findings[0].location.line is None


def test_candidate_with_cwe_outside_top25_is_invalid_and_uses_fallback(tmp_path):
    model = ScriptedChainBackend(
        [
            _summary_reply(),
            _candidate_reply(cwe=999),
            {"findings": []},
        ]
    )

    record, findings = run_one(
        _benchmark(tmp_path, vulnerable=True),
        "A9",
        model=model,
    )

    assert record.error is None
    assert findings == []
    assert len(model.calls) == 3
    assert record.trace["candidate_parse_failures"] == 1
    assert record.trace["invalid_candidates"] == 1
    assert "candidate extraction failed" in model.calls[2][1]["content"].lower()


def test_usage_from_all_three_completions_is_summed(tmp_path):
    model = ScriptedChainBackend(
        [_summary_reply(), _candidate_reply(), _finding_reply()],
        usages=[
            Usage(input_tokens=10, output_tokens=1),
            Usage(input_tokens=20, output_tokens=2),
            Usage(input_tokens=30, output_tokens=3),
        ],
    )

    record, _ = run_one(_benchmark(tmp_path, vulnerable=True), "A9", model=model)

    assert record.error is None
    assert record.input_tokens == 60
    assert record.output_tokens == 6
    assert record.trace["model_calls"] == 3


def test_safe_empty_candidate_path_bills_only_two_completions(tmp_path):
    model = ScriptedChainBackend(
        [_summary_reply(), {"candidates": []}],
        usages=[
            Usage(input_tokens=10, output_tokens=1),
            Usage(input_tokens=20, output_tokens=2),
        ],
    )

    record, _ = run_one(_benchmark(tmp_path, vulnerable=False), "A9", model=model)

    assert record.error is None
    assert record.input_tokens == 30
    assert record.output_tokens == 3
    assert record.trace["model_calls"] == 2


def test_empty_selected_file_remains_in_scoring_denominator(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text("")
    (src / "BenchmarkTest00002.java").write_text("int result = 1 + 1;\n")
    expected = tmp_path / "expectedresults-1.2.csv"
    expected.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
    )
    target = Target(
        name="a9-two-file-fixture",
        kind=TargetKind.BENCHMARK,
        source_path=str(src),
        ground_truth=str(expected),
    )
    model = ScriptedChainBackend([_summary_reply(), {"candidates": []}])

    record, findings = run_one(target, "A9", model=model)

    assert record.error is None
    assert findings == []
    assert record.metrics["fn"] == 1
    assert record.metrics["tn"] == 1
    assert record.trace["files_selected"] == 2
    assert record.trace["files_scanned"] == 1


def test_empty_source_tree_scores_an_empty_benchmark_scope(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    expected = tmp_path / "expectedresults-1.2.csv"
    expected.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
    )
    target = Target(
        name="a9-empty-fixture",
        kind=TargetKind.BENCHMARK,
        source_path=str(src),
        ground_truth=str(expected),
    )

    record, findings = run_one(target, "A9", model=ScriptedChainBackend([]))

    assert record.error is None
    assert findings == []
    assert record.metrics["tp"] == 0
    assert record.metrics["fp"] == 0
    assert record.metrics["fn"] == 0
    assert record.metrics["tn"] == 0
    assert record.trace["files_selected"] == 0
    assert record.trace["model_calls"] == 0


def test_trace_records_truncation_and_versioned_prompt_hashes(tmp_path):
    model = ScriptedChainBackend([_summary_reply(), {"candidates": []}])

    record, _ = run_one(
        _benchmark(tmp_path, vulnerable=True),
        "A9",
        model=model,
        config={"max_file_bytes": 10},
    )

    assert record.error is None
    assert record.trace["truncated_files"] == 1
    assert record.trace["max_file_bytes"] == 10
    assert record.trace["prompt_version"]
    assert {"summary", "candidates", "verify", "fallback_verify"} <= set(
        record.trace["prompt_hashes"]
    )
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", digest)
        for digest in record.trace["prompt_hashes"].values()
    )


def test_plain_mock_backend_completes_without_error(tmp_path):
    record, findings = run_one(
        _benchmark(tmp_path, vulnerable=False),
        "A9",
        model=MockBackend(),
    )

    assert record.error is None
    assert findings == []
    assert record.trace["model_calls"] == 3
