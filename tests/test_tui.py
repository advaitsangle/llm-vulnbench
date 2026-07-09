"""Unit tests for the shared terminal widgets (no real terminal involved)."""

from __future__ import annotations

import io

import pytest

from vulnbench import tui
from vulnbench.tui import _read_key, _text_select, parse_numeric_selection, select


def test_parse_numeric_selection_filters_and_dedups():
    assert parse_numeric_selection("1 3 3 9", count=4) == [0, 2]  # 9 out of range, dup dropped
    assert parse_numeric_selection("2,1", count=4) == [0, 1]      # commas, sorted
    assert parse_numeric_selection("nope", count=4) == []


@pytest.mark.parametrize(
    ("raw", "token"),
    [
        ("\x1b[A", "up"),
        ("\x1b[B", "down"),
        ("\r", "enter"),
        ("\n", "enter"),
        (" ", "space"),
        ("\x1b", "quit"),   # a lone ESC cancels
        ("Q", "q"),         # lowercased
    ],
)
def test_read_key_tokens(raw, token):
    assert _read_key(io.StringIO(raw)) == token


def test_read_key_ctrl_c_raises():
    with pytest.raises(KeyboardInterrupt):
        _read_key(io.StringIO("\x03"))


def test_text_select_parses_numbers(monkeypatch, capsys):
    monkeypatch.setattr(tui, "prompt", lambda *a, **k: "1 3")
    assert _text_select(["a", "b", "c"], set()) == [0, 2]


def test_text_select_all_and_cancel(monkeypatch):
    monkeypatch.setattr(tui, "prompt", lambda *a, **k: "all")
    assert _text_select(["a", "b"], set()) == [0, 1]
    monkeypatch.setattr(tui, "prompt", lambda *a, **k: "")
    assert _text_select(["a", "b"], set()) is None


def test_select_uses_text_frontend_when_not_a_tty(monkeypatch):
    monkeypatch.setattr(tui, "is_interactive", lambda: False)
    monkeypatch.setattr(tui, "prompt", lambda *a, **k: "2")
    assert select(["a", "b"]) == [1]


def test_select_on_empty_rows_short_circuits(monkeypatch):
    # No menu, no prompt — an empty option list has exactly one answer.
    monkeypatch.setattr(tui, "is_interactive", lambda: True)
    assert select([]) == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
