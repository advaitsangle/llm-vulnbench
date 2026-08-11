"""A5: the reducer cuts the file down, then B3's evaluation runs on the cut.

A role-aware MockBackend answers the reducer and the evaluator differently (told apart
by the system prompt) and records every evaluator prompt, so the handoff between the two
iterations is assertable offline.
"""

import json

from vulnbench.conditions.b3_llm import _user_prompt as b3_user_prompt
from vulnbench.corpus import Target, TargetKind
from vulnbench.harness import run_one
from vulnbench.models import MockBackend
from vulnbench.models.base import Completion, Usage

SINK = 'String q = "SELECT * FROM u WHERE id=" + req.getParameter("id");'
# Enough surrounding noise that cutting down to SINK is a real reduction.
BOILERPLATE = "\n".join(f"import java.util.pkg{n}.Thing{n};" for n in range(6))


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


def _last_code_line(prompt: str) -> str:
    """The last non-blank line of the fenced file in a prompt — a faithful 'cut'."""
    body = prompt.split("```")[1]
    return [ln for ln in body.splitlines() if ln.strip()][-1]


class ReducerBackend(MockBackend):
    """Scripts both iterations.

    ``chunk=None`` (the default) is an honest reducer: it copies the last real line out
    of whichever file it was shown. Pass a ``chunk`` to script a specific reply — ``""``
    for "nothing risky here", or invented code to exercise the fidelity metric.
    """

    def __init__(self, chunk: str | None = None):
        super().__init__()
        self.chunk = chunk
        self.reduce_prompts: list[str] = []
        self.eval_prompts: list[str] = []

    def _complete(self, messages, tools=None, **kwargs):
        sys = messages[0]["content"]
        user = messages[1]["content"]
        if "code reducer" in sys:
            self.reduce_prompts.append(user)
            chunk = self.chunk if self.chunk is not None else _last_code_line(user)
            text = json.dumps({"chunk": chunk, "reason": "param into SQL"})
        else:  # the evaluator — B3's own prompt
            self.eval_prompts.append(user)
            text = json.dumps(
                {"findings": [{"cwe": 89, "verdict": "confirmed", "confidence": 0.8,
                               "evidence": "tainted concat"}]}
            )
        return Completion(text=text, usage=Usage(input_tokens=1, output_tokens=1))


def test_evaluator_sees_only_the_reduced_chunk(tmp_path):
    model = ReducerBackend()
    record, findings = run_one(_benchmark(tmp_path), "A5", model=model)
    assert record.error is None
    assert any(f.vuln_class == 89 for f in findings)
    assert record.metrics["tp"] == 1  # the real case is detected
    # The evaluator got the risky line and never the boilerplate the reducer dropped.
    assert any(SINK in p for p in model.eval_prompts)
    assert all(BOILERPLATE not in p for p in model.eval_prompts)
    assert record.trace["files_reduced"] == 2
    assert record.trace["pruned_frac"] > 0


def test_evaluation_prompt_is_b3s_prompt(tmp_path):
    """Iteration 2 *is* B3: same prompt, only the code differs. Pin that."""
    target = _benchmark(tmp_path)
    model = ReducerBackend()
    run_one(target, "A5", model=model)
    path = f"{target.source_path}/BenchmarkTest00001.java"
    assert b3_user_prompt(path, SINK) in model.eval_prompts


def test_both_iterations_are_billed(tmp_path):
    model = ReducerBackend()
    record, _ = run_one(_benchmark(tmp_path), "A5", model=model)
    # Two files x (one reducer call + one evaluator call).
    assert len(model.reduce_prompts) == 2
    assert len(model.eval_prompts) == 2
    assert record.input_tokens == 4  # the reducer's cost is charged to A5, not hidden


def test_empty_reduction_falls_back_to_the_full_file(tmp_path):
    model = ReducerBackend(chunk="")
    record, findings = run_one(_benchmark(tmp_path), "A5", model=model)
    assert record.error is None
    assert record.trace["files_full_fallback"] == 2
    assert record.trace["files_reduced"] == 0
    assert record.trace["chunk_fidelity"] is None  # nothing was reduced to measure
    # Fell back to plain B3 on both files: the whole file reached the evaluator.
    assert all(BOILERPLATE in p for p in model.eval_prompts)
    assert any(f.vuln_class == 89 for f in findings)


def test_on_empty_skip_leaves_the_file_unexamined(tmp_path):
    model = ReducerBackend(chunk="")
    record, findings = run_one(
        _benchmark(tmp_path), "A5", model=model, config={"on_empty": "skip"}
    )
    assert record.error is None
    assert record.trace["files_skipped_empty"] == 2
    assert model.eval_prompts == []
    assert findings == []
    assert record.metrics["fn"] == 1  # skipping costs recall, honestly


def test_reduce_off_is_plain_b3(tmp_path):
    target = _benchmark(tmp_path)
    model = ReducerBackend()
    record, findings = run_one(target, "A5", model=model, config={"reduce": False})
    assert record.error is None
    assert model.reduce_prompts == []  # no reducer pass at all
    path = f"{target.source_path}/BenchmarkTest00001.java"
    assert b3_user_prompt(path, f"{BOILERPLATE}\n{SINK}\n") in model.eval_prompts
    assert record.trace["pruned_frac"] == 0.0
    assert any(f.vuln_class == 89 for f in findings)


def test_fidelity_flags_a_reducer_that_invents_code(tmp_path):
    # A chunk whose lines are nowhere in the source: the evaluator judged fiction.
    model = ReducerBackend(chunk='exec("rm -rf /");')
    record, _ = run_one(_benchmark(tmp_path), "A5", model=model)
    assert record.trace["chunk_fidelity"] == 0.0
    # ...while a copying reducer scores a clean 1.0.
    record, _ = run_one(_benchmark(tmp_path), "A5", model=ReducerBackend())
    assert record.trace["chunk_fidelity"] == 1.0


def test_max_chunk_bytes_truncates_the_handoff(tmp_path):
    model = ReducerBackend(chunk=SINK)
    record, _ = run_one(
        _benchmark(tmp_path), "A5", model=model, config={"max_chunk_bytes": 10}
    )
    assert record.error is None
    assert all(SINK[:10] in p and SINK not in p for p in model.eval_prompts)
