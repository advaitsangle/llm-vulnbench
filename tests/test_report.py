"""Unit tests for the comparative matrix rendering (plain mode; no rich needed)."""

from __future__ import annotations

import pytest

from vulnbench.harness import RunRecord
from vulnbench.report import Reporter, _best_f1, _matrix_cells


def _rec(target="t", model="m", condition="B1", f1=0.5, error=None, **kw):
    metrics = None if error else {"precision": 0.6, "recall": 0.4, "f1": f1, "fpr": 0.1}
    return RunRecord(
        target=target, condition=condition, model=model, metrics=metrics,
        input_tokens=kw.get("input_tokens", 10), output_tokens=kw.get("output_tokens", 5),
        seconds=kw.get("seconds", 1.0), model_seconds=0.0,
        n_findings=kw.get("n_findings", 3), error=error,
    )


def test_best_f1_picks_the_highest_scored_cell():
    recs = [_rec(f1=0.2), _rec(f1=0.9), _rec(f1=0.5)]
    assert _best_f1(recs) == 1


def test_best_f1_ties_go_to_the_first_cell():
    assert _best_f1([_rec(f1=0.7), _rec(f1=0.7)]) == 0


def test_best_f1_ignores_errored_and_unscored_cells():
    # An errored cell has no metrics; an unscored one has metrics=None too.
    recs = [_rec(error="boom"), _rec(f1=0.3)]
    assert _best_f1(recs) == 1
    assert _best_f1([_rec(error="boom")]) is None


def test_matrix_cells_marks_error_without_metrics():
    cells = _matrix_cells(_rec(error="RuntimeError: boom"))
    assert cells[:3] == ["t", "m", "B1"]
    assert cells[3] == "error"
    assert set(cells[4:]) == {"—"}


def test_matrix_cells_render_metrics_and_totals():
    cells = _matrix_cells(_rec(f1=0.75, n_findings=7, seconds=2.5, input_tokens=10, output_tokens=5))
    assert cells[3] == "7"
    assert cells[6] == "0.75"          # F1
    assert cells[8] == "2.5s"          # latency
    assert cells[9] == "15"            # input + output tokens


def test_matrix_cells_never_embed_the_best_marker():
    """The marker lives in its own column; folding it in would skew fixed-width fields."""
    assert _matrix_cells(_rec(f1=0.75))[6] == "0.75"


def test_matrix_plain_lists_every_config_and_marks_the_best(capsys):
    recs = [
        _rec(target="bench", model="qwen", condition="B1", f1=0.30),
        _rec(target="bench", model="qwen", condition="C1", f1=0.80),
        _rec(target="juice", model="opus", condition="C1", f1=0.60),
    ]
    Reporter(pretty=False).matrix(recs, {"scorecard": "card.json"})
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if " B1 " in ln or " C1 " in ln]
    assert len(lines) == 3                       # one row per configuration
    best = next(ln for ln in lines if "0.80" in ln)
    assert best.startswith("*")                  # highest F1 is starred
    assert not any(ln.startswith("*") for ln in lines if "0.80" not in ln)
    assert "scorecard -> card.json" in out


def test_plain_tracker_distinguishes_a_resumed_cell_from_a_running_one(capsys):
    """A checkpoint hit must not announce itself as running."""
    with Reporter(pretty=False).track(2) as tracker:
        tracker.start("B1", "bench")
        tracker.start("C1", "bench", resumed=True)
    out = capsys.readouterr().out
    assert "… running B1 on bench" in out
    assert "… resumed C1 on bench" in out
    assert "running C1" not in out


def test_matrix_plain_handles_no_scored_cells(capsys):
    Reporter(pretty=False).matrix([_rec(error="boom")], {})
    out = capsys.readouterr().out
    assert "best F1" not in out                  # nothing to star
    assert "error" in out


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
