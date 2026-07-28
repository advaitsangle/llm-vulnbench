"""A2 (AST-augmented context): the model must see AST text, not raw source.
"""

from __future__ import annotations

import json

import vulnbench.conditions.a2_ast_context as a2_mod
from vulnbench.conditions.a2_ast_context import A2ASTContext
from vulnbench.conditions.base import ConditionContext
from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models import Completion, MockBackend, Usage


class _CapturingModel(MockBackend):
    """Records every prompt it's asked to complete; returns one confirmed finding."""

    def __init__(self):
        super().__init__()
        self.name = "fake"
        self.calls: list[str] = []

    def _complete(self, messages, tools=None, **kwargs):
        self.calls.append(messages[-1]["content"])
        return Completion(
            text=json.dumps({"findings": [
                {"cwe": 89, "file": None, "line": 4,
                 "verdict": "confirmed", "confidence": 0.9, "evidence": "tainted query"}
            ]}),
            usage=Usage(input_tokens=3, output_tokens=5),
        )


_FAKE_TREE = object()  # a sentinel: real shape doesn't matter, render_ast is patched too


def _patch_ast(monkeypatch, *, parse_ok: bool):
    monkeypatch.setattr(
        a2_mod.ast_support, "parse_tree",
        lambda path, code: _FAKE_TREE if parse_ok else None,
    )
    monkeypatch.setattr(
        a2_mod.ast_support, "render_ast",
        lambda tree, max_chars: ("method_declaration [L1]\nif_statement [L2]", False),
    )


def _one_file_target(tmp_path, code: str) -> Target:
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text(code)
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text(
        "# name, category, real, cwe\nBenchmarkTest00001,sqli,true,89\n"
    )
    return Target("t", TargetKind.BENCHMARK, source_path=str(src), ground_truth=str(csv))


def test_a2_sends_ast_text_not_raw_source(tmp_path, monkeypatch):
    _patch_ast(monkeypatch, parse_ok=True)
    target = _one_file_target(
        tmp_path, 'String q = "SELECT * FROM u WHERE id=" + id;\n'
    )
    model = _CapturingModel()
    result = A2ASTContext().run(target, ConditionContext(model=model))

    assert len(model.calls) == 1
    prompt = model.calls[0]
    assert "method_declaration [L1]" in prompt          # the rendered AST is present
    assert "SELECT * FROM u WHERE id" not in prompt      # raw source text is not
    assert "abstract syntax tree" in prompt              # the model is told what it's seeing
    assert result.trace["ast_fallback_files"] == 0
    assert len(result.findings) == 1
    assert result.findings[0].location.file == str(tmp_path / "src" / "BenchmarkTest00001.java")


def test_a2_falls_back_to_raw_source_when_unparsable(tmp_path, monkeypatch):
    _patch_ast(monkeypatch, parse_ok=False)
    target = _one_file_target(tmp_path, "SELECT injected into a .weird extension\n")
    model = _CapturingModel()
    result = A2ASTContext().run(target, ConditionContext(model=model))

    prompt = model.calls[0]
    assert "SELECT injected into a .weird extension" in prompt  # raw source shows up
    assert "raw source" in prompt                                 # and is labeled as such
    assert result.trace["ast_fallback_files"] == 1


def test_a2_registered_and_scores_end_to_end(tmp_path, monkeypatch):
    _patch_ast(monkeypatch, parse_ok=True)
    target = _one_file_target(
        tmp_path, 'String q = "SELECT * FROM u WHERE id=" + id;\n'
    )
    record, findings = run_one(target, "A2", model=_CapturingModel())
    assert record.error is None
    assert record.metrics["tp"] == 1
    assert any(f.vuln_class == 89 for f in findings)


def test_a2_respects_sample_files(tmp_path, monkeypatch):
    _patch_ast(monkeypatch, parse_ok=True)
    src = tmp_path / "src"
    src.mkdir()
    for i in range(5):
        (src / f"BenchmarkTest0000{i}.java").write_text("int x = 1;\n")
    target = Target("t", TargetKind.BENCHMARK, source_path=str(src))
    model = _CapturingModel()
    A2ASTContext().run(target, ConditionContext(model=model, config={"sample_files": 2}))
    assert len(model.calls) == 2
