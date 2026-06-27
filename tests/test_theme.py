import pytest

from vulnbench import theme


@pytest.fixture(autouse=True)
def _reset_plain():
    theme.set_plain(False)
    yield
    theme.set_plain(False)


def test_paint_is_noop_without_a_tty(monkeypatch):
    monkeypatch.setattr(theme.sys.stdout, "isatty", lambda: False, raising=False)
    assert theme.paint("hi", "blue", bold=True) == "hi"


def test_paint_colors_on_a_tty(monkeypatch):
    monkeypatch.setattr(theme.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    out = theme.paint("hi", "blue")
    assert out != "hi" and out.startswith("\x1b[") and out.endswith("\x1b[0m")


def test_set_plain_disables_color_even_on_a_tty(monkeypatch):
    monkeypatch.setattr(theme.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    theme.set_plain(True)
    assert theme.paint("hi", "blue") == "hi"          # ANSI front-end off
    assert theme.make_console(True) is None           # rich front-end off too


def test_no_color_env_disables_color(monkeypatch):
    monkeypatch.setattr(theme.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    assert theme.paint("hi", "blue") == "hi"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
