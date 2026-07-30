"""A3 (CFG/DFG-augmented context): the model must see the CFG/DFG sketch, not
raw source.
"""

from __future__ import annotations

import json

import vulnbench.conditions.a3_cfg_dfg_context as a3_mod
from vulnbench.conditions.a3_cfg_dfg_context import A3CFGDFGContext
from vulnbench.conditions.base import ConditionContext
from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models import Completion, MockBackend, Usage

_FAKE_TREE = object()
_FAKE_CFG_TEXT = "FUNCTION bar (L1-L3)\n  B1 [STMT L2] String q = ...;\n  DFG:\n    q: def=L2 use=-"


class _CapturingModel(MockBackend):
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


def _patch_ast(monkeypatch, *, parse_ok: bool):
    monkeypatch.setattr(
        a3_mod.ast_support, "parse_tree",
        lambda path, code: _FAKE_TREE if parse_ok else None,
    )
    monkeypatch.setattr(
        a3_mod, "build_cfg_dfg",
        lambda tree, max_chars: (_FAKE_CFG_TEXT, False),
    )


def _one_file_target(tmp_path, code: str) -> Target:
    src = tmp_path / "src"
    src.mkdir()
    (src / "BenchmarkTest00001.java").write_text(code)
    csv = tmp_path / "expectedresults-1.2.csv"
    csv.write_text("# name, category, real, cwe\nBenchmarkTest00001,sqli,true,89\n")
    return Target("t", TargetKind.BENCHMARK, source_path=str(src), ground_truth=str(csv))


def test_a3_sends_cfg_dfg_text_not_raw_source(tmp_path, monkeypatch):
    _patch_ast(monkeypatch, parse_ok=True)
    target = _one_file_target(
        tmp_path, 'String q = "SELECT * FROM u WHERE id=" + id;\n'
    )
    model = _CapturingModel()
    result = A3CFGDFGContext().run(target, ConditionContext(model=model))

    assert len(model.calls) == 1
    prompt = model.calls[0]
    assert "FUNCTION bar (L1-L3)" in prompt               # the rendered CFG/DFG is present
    assert "SELECT * FROM u WHERE id" not in prompt        # raw source text is not
    assert "control-flow graph" in prompt                  # the model is told what it's seeing
    assert result.trace["cfg_fallback_files"] == 0
    assert len(result.findings) == 1
    assert result.findings[0].location.file == str(tmp_path / "src" / "BenchmarkTest00001.java")


def test_a3_falls_back_to_raw_source_when_unparsable(tmp_path, monkeypatch):
    _patch_ast(monkeypatch, parse_ok=False)
    target = _one_file_target(tmp_path, "some .weird extension content\n")
    model = _CapturingModel()
    result = A3CFGDFGContext().run(target, ConditionContext(model=model))

    prompt = model.calls[0]
    assert "some .weird extension content" in prompt   # raw source shows up
    assert "raw source" in prompt                       # and is labeled as such
    assert result.trace["cfg_fallback_files"] == 1


def test_a3_falls_back_when_cfg_text_is_empty(tmp_path, monkeypatch):
    # A parse that succeeds but yields no CFG text (e.g. a file with no
    # function-like node at all) is also a fallback, not an empty prompt.
    monkeypatch.setattr(a3_mod.ast_support, "parse_tree", lambda path, code: _FAKE_TREE)
    monkeypatch.setattr(a3_mod, "build_cfg_dfg", lambda tree, max_chars: ("", False))
    target = _one_file_target(tmp_path, "package-level constant X = 1;\n")
    model = _CapturingModel()
    result = A3CFGDFGContext().run(target, ConditionContext(model=model))

    prompt = model.calls[0]
    assert "package-level constant X = 1;" in prompt
    assert result.trace["cfg_fallback_files"] == 1


def test_a3_registered_and_scores_end_to_end(tmp_path, monkeypatch):
    _patch_ast(monkeypatch, parse_ok=True)
    target = _one_file_target(
        tmp_path, 'String q = "SELECT * FROM u WHERE id=" + id;\n'
    )
    record, findings = run_one(target, "A3", model=_CapturingModel())
    assert record.error is None
    assert record.metrics["tp"] == 1
    assert any(f.vuln_class == 89 for f in findings)


def test_a3_respects_sample_files(tmp_path, monkeypatch):
    _patch_ast(monkeypatch, parse_ok=True)
    src = tmp_path / "src"
    src.mkdir()
    for i in range(5):
        (src / f"BenchmarkTest0000{i}.java").write_text("int x = 1;\n")
    target = Target("t", TargetKind.BENCHMARK, source_path=str(src))
    model = _CapturingModel()
    A3CFGDFGContext().run(target, ConditionContext(model=model, config={"sample_files": 2}))
    assert len(model.calls) == 2
